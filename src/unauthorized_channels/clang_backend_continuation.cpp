// Experimental native backend cutpoint. This is not a closure certificate.
// Link against the authentic compiler libraries with --wrap=EmitBackendOutput.
#include "clang/Basic/Diagnostic.h"
#include "clang/Basic/SourceManager.h"
#include "clang/CodeGen/BackendUtil.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/CompilerInvocation.h"
#include "clang/Frontend/FrontendDiagnostic.h"
#include "clang/Frontend/TextDiagnosticBuffer.h"
#include "clang/Frontend/Utils.h"
#include "clang/FrontendTool/Utils.h"
#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/CallSite.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/InitLLVM.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/Signals.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/Timer.h"
#include "llvm/Support/raw_ostream.h"
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>
#include <vector>
#include <sys/resource.h>
#include <unistd.h>

using namespace clang;
using namespace llvm;

namespace {
std::vector<std::string> invocation;
using Bytes = std::string;
bool nativeFinishReports = false;

void set_native_finish_reports(const CompilerInstance &compiler) {
  const auto &options = compiler.getFrontendOpts();
  nativeFinishReports = options.ShowTimers || options.ShowStats || !options.StatsFile.empty();
}

bool native_report_options() {
  if (nativeFinishReports) return true;
  // These parsed native options expose pass activity outside the recipe tape.
  // This covers named report modes, not all LLVM globals or backend effects.
  auto &options = llvm::cl::getRegisteredOptions();
  for (StringRef name : {"debug-pass", "time-passes", "stats", "stats-json",
                        "print-before", "print-after", "print-before-all", "print-after-all"}) {
    auto option = options.find(name);
    if (option != options.end() && option->second->getNumOccurrences()) return true;
  }
  return false;
}

// The native cc1 entry installs this handler before executing frontend actions.
// LLVM stream failures must use native diagnostics and interrupt cleanup too.
void backend_fatal(void *context, const std::string &message, bool crashDiagnostics) {
  auto &diagnostics = *static_cast<DiagnosticsEngine *>(context);
  diagnostics.Report(diag::err_fe_error_backend) << message;
  llvm::sys::RunInterruptHandlers();
  std::exit(crashDiagnostics ? 70 : 1);
}

void number(Bytes &out, uint64_t value) {
  for (unsigned i = 0; i != 8; ++i) out.push_back(char(value >> (8 * i)));
}
void field(Bytes &out, StringRef value) {
  number(out, value.size()); out.append(value.data(), value.size());
}
struct Reader {
  StringRef bytes;
  size_t offset = 0;
  bool valid = true;
  uint64_t number() {
    if (bytes.size() - offset < 8) { valid = false; return 0; }
    uint64_t result = 0;
    for (unsigned i = 0; i != 8; ++i)
      result |= uint64_t(uint8_t(bytes[offset++])) << (8 * i);
    return result;
  }
  Bytes field() {
    auto size = number();
    if (!valid || size > bytes.size() - offset) { valid = false; return {}; }
    auto result = bytes.substr(offset, size).str(); offset += size; return result;
  }
};
bool send(StringRef bytes) {
  while (!bytes.empty()) {
    auto count = ::write(STDOUT_FILENO, bytes.data(), bytes.size());
    if (count <= 0) return false;
    bytes = bytes.drop_front(count);
  }
  return true;
}
Bytes receive() {
  Bytes result;
  char buffer[65536];
  ssize_t count;
  while ((count = ::read(STDIN_FILENO, buffer, sizeof(buffer))) > 0) {
    if (result.size() + count > 128 * 1024 * 1024) return {};
    result.append(buffer, count);
  }
  return count < 0 ? Bytes() : result;
}

// This conservative assembly domain contains a single mnemonic, no operands
// or assembler directives. Other assembly remains a native private action.
bool mnemonic(StringRef text) {
  text = text.trim();
  if (text.empty()) return true;
  if (!(std::isalpha(uint8_t(text.front())) || text.front() == '_')) return false;
  for (char c : text)
    if (!(std::isalnum(uint8_t(c)) || c == '_')) return false;
  return true;
}
bool candidate(llvm::Module &module, SourceManager &sm) {
  if (sm.loaded_sloc_entry_size() || !mnemonic(module.getModuleInlineAsm())) return false;
  for (auto &function : module)
    for (auto &block : function)
      for (auto &instruction : block)
        if (CallSite call = CallSite(&instruction))
          if (auto *assembly = dyn_cast<InlineAsm>(call.getCalledValue()))
            if (!mnemonic(assembly->getAsmString())) return false;
  return true;
}

#ifdef RGEC_RESIDUAL_BUILD
void append_residual_state(Bytes &, llvm::Module &, SourceManager &);
#ifdef RGEC_READ_BUILD
void append_native_read_state(Bytes &);
bool restore_native_read_state(Reader &);
bool project_native_read_state(Reader &);
#endif
StringRef residual_input_bitcode(llvm::Module &);
#endif
Bytes state(llvm::Module &module, SourceManager &sm) {
  Bytes result;
  number(result, invocation.size());
  for (auto &argument : invocation) field(result, argument);
  SmallVector<char, 0> bitcode;
  raw_svector_ostream stream(bitcode);
#ifdef RGEC_RESIDUAL_BUILD
  // A producer's input is the received bitcode encoding. Parsing and writing
  // it can reorder records; reserialization is not its input identity.
  auto captured = residual_input_bitcode(module);
  if (!captured.empty()) field(result, captured);
  else {
#endif
  WriteBitcodeToFile(module, stream, true);
  field(result, StringRef(bitcode.data(), bitcode.size()));
#ifdef RGEC_RESIDUAL_BUILD
  }
#endif
  number(result, sm.local_sloc_entry_size());
  number(result, sm.getNextLocalOffset());
  for (unsigned i = 1; i < sm.local_sloc_entry_size(); ++i) {
    auto &entry = sm.getLocalSLocEntry(i);
    number(result, entry.getOffset()); number(result, entry.isFile());
    if (entry.isFile()) {
      auto location = SourceLocation::getFromRawEncoding(entry.getOffset());
      number(result, entry.getFile().getIncludeLoc().getRawEncoding());
      number(result, entry.getFile().getFileCharacteristic());
      field(result, sm.getBufferName(location));
      field(result, sm.getBufferData(sm.getFileID(location)));
    } else {
      auto &expansion = entry.getExpansion();
      number(result, expansion.getSpellingLoc().getRawEncoding());
      number(result, expansion.getExpansionLocStart().getRawEncoding());
      number(result, expansion.getExpansionLocEnd().getRawEncoding());
      number(result, expansion.isExpansionTokenRange());
    }
  }
#ifdef RGEC_RESIDUAL_BUILD
  append_residual_state(result, module, sm);
#ifdef RGEC_READ_BUILD
  append_native_read_state(result);
#endif
#endif
  return result;
}

struct Operation { unsigned kind; Bytes data; uint64_t offset = 0; };
struct Frame { unsigned offset, characteristic; Bytes name, data; };
struct Recipe {
  Bytes key;
  bool reusable = true;
  std::vector<Frame> frames;
  std::vector<Operation> operations;
#ifdef RGEC_RESIDUAL_BUILD
  bool nativeDiagnosticContinuation = false;
  bool computationScopeAllowed = true;
  Bytes computationKey;
#endif
};
class RecordingStream : public raw_pwrite_stream {
  std::unique_ptr<raw_pwrite_stream> native;
  Recipe &recipe;
  void write_impl(const char *data, size_t size) override {
    recipe.operations.push_back({0, Bytes(data, size), 0});
    native->write(data, size);
  }
  void pwrite_impl(const char *data, size_t size, uint64_t offset) override {
    recipe.operations.push_back({1, Bytes(data, size), offset});
    native->pwrite(data, size, offset);
  }
  uint64_t current_pos() const override { return native->tell(); }
public:
  RecordingStream(std::unique_ptr<raw_pwrite_stream> native, Recipe &recipe)
      : native(std::move(native)), recipe(recipe) { SetUnbuffered(); }
};
class RecordingDiagnostics : public DiagnosticConsumer {
  DiagnosticConsumer &native;
  Recipe &recipe;
public:
  RecordingDiagnostics(DiagnosticConsumer &native, Recipe &recipe)
      : native(native), recipe(recipe) {}
  void HandleDiagnostic(DiagnosticsEngine::Level level, const Diagnostic &info) override {
#ifdef RGEC_RESIDUAL_BUILD
    if (recipe.nativeDiagnosticContinuation) {
      DiagnosticConsumer::HandleDiagnostic(level, info);
      native.HandleDiagnostic(level, info);
      return;
    }
#endif
    Bytes data;
    number(data, info.getID()); number(data, info.getLocation().getRawEncoding());
    number(data, info.getNumArgs());
    for (unsigned i = 0; i < info.getNumArgs(); ++i) {
      auto kind = info.getArgKind(i);
      number(data, kind);
      switch (kind) {
      case DiagnosticsEngine::ak_std_string: field(data, info.getArgStdStr(i)); break;
      case DiagnosticsEngine::ak_c_string: field(data, info.getArgCStr(i)); break;
      case DiagnosticsEngine::ak_sint: number(data, uint32_t(info.getArgSInt(i))); break;
      case DiagnosticsEngine::ak_uint: number(data, info.getArgUInt(i)); break;
      default: recipe.reusable = false; number(data, 0); break;
      }
    }
    number(data, info.getNumRanges());
    for (auto range : info.getRanges()) {
      number(data, range.getBegin().getRawEncoding());
      number(data, range.getEnd().getRawEncoding()); number(data, range.isTokenRange());
    }
    if (info.getNumFixItHints()) recipe.reusable = false;
#ifdef RGEC_RESIDUAL_BUILD
    field(data, info.getDiags()->getFlagValue());
    recipe.operations.push_back({7, std::move(data), 0});
#else
    recipe.operations.push_back({2, std::move(data), 0});
#endif
    DiagnosticConsumer::HandleDiagnostic(level, info);
    native.HandleDiagnostic(level, info);
  }
};

Bytes encode(const Recipe &recipe) {
  Bytes result = "RGECB1";
#ifdef RGEC_RESIDUAL_BUILD
  if (!recipe.computationKey.empty()) result = "RGECB2";
#endif
  field(result, recipe.key);
#ifdef RGEC_RESIDUAL_BUILD
  if (!recipe.computationKey.empty()) field(result, recipe.computationKey);
#endif
  number(result, recipe.reusable);
  number(result, recipe.frames.size());
  for (auto &frame : recipe.frames) {
    number(result, frame.offset); number(result, frame.characteristic);
    field(result, frame.name); field(result, frame.data);
  }
  number(result, recipe.operations.size());
  for (auto &operation : recipe.operations) {
    number(result, operation.kind); number(result, operation.offset); field(result, operation.data);
  }
  return result;
}
bool decode(StringRef bytes, Recipe &recipe) {
  bool parametric = false;
  bool compact = false;
#ifdef RGEC_RESIDUAL_BUILD
  compact = bytes.startswith("RGECB3");
  parametric = bytes.startswith("RGECB2") || compact;
#endif
  if (!bytes.startswith("RGECB1") && !parametric) return false;
  Reader reader{bytes.drop_front(6)};
  if (!compact) recipe.key = reader.field();
#ifdef RGEC_RESIDUAL_BUILD
  if (parametric) {
    recipe.computationKey = reader.field();
    if (!StringRef(recipe.computationKey).startswith("RGECK1")) return false;
  }
#endif
  recipe.reusable = reader.number() == 1;
  auto frames = reader.number();
  if (!reader.valid || frames > 10000) return false;
  for (unsigned i = 0; i < frames; ++i) {
    Frame frame;
    frame.offset = reader.number(); frame.characteristic = reader.number();
    frame.name = reader.field(); frame.data = reader.field();
    recipe.frames.push_back(std::move(frame));
  }
  auto operations = reader.number();
  if (!reader.valid || operations > 1000000) return false;
  uint64_t written = 0;
  for (unsigned i = 0; i < operations; ++i) {
    Operation operation;
    operation.kind = reader.number(); operation.offset = reader.number(); operation.data = reader.field();
    if (operation.kind == 0) written += operation.data.size();
    else if (operation.kind == 1) {
      if (operation.offset > written || operation.data.size() > written - operation.offset) return false;
#ifdef RGEC_RESIDUAL_BUILD
    } else if (operation.kind == 7) {
#else
    } else if (operation.kind == 2) {
#endif
      Reader diagnostic{operation.data};
      diagnostic.number(); diagnostic.number();
      auto arguments = diagnostic.number();
      if (arguments > 10) return false;
      for (unsigned j = 0; j < arguments; ++j) {
        auto kind = diagnostic.number();
        if (kind == DiagnosticsEngine::ak_std_string || kind == DiagnosticsEngine::ak_c_string) diagnostic.field();
        else if (kind == DiagnosticsEngine::ak_sint || kind == DiagnosticsEngine::ak_uint) diagnostic.number();
        else return false;
      }
      auto ranges = diagnostic.number();
      if (ranges > 10) return false;
      for (unsigned j = 0; j < ranges * 3; ++j) diagnostic.number();
#ifdef RGEC_RESIDUAL_BUILD
      diagnostic.field();
#endif
      if (!diagnostic.valid || diagnostic.offset != diagnostic.bytes.size()) return false;
#ifdef RGEC_RESIDUAL_BUILD
    } else if (operation.kind == 5) {
      Reader diagnostic{operation.data}; diagnostic.field(); diagnostic.number(); diagnostic.number();
      if (!diagnostic.valid || diagnostic.offset != diagnostic.bytes.size()) return false;
    } else if (operation.kind == 6) {
      Reader diagnostic{operation.data}; diagnostic.field(); diagnostic.number(); diagnostic.number();
      diagnostic.field(); diagnostic.field();
      if (!diagnostic.valid || diagnostic.offset != diagnostic.bytes.size()) return false;
    } else if (operation.kind == 8) {
      Reader diagnostic{operation.data}; auto kind = diagnostic.number();
      if (!diagnostic.valid || kind > 2 || diagnostic.offset != diagnostic.bytes.size()) return false;
    } else if (operation.kind == 9) {
      Reader diagnostic{operation.data};
      for (unsigned j = 0; j < 4; ++j) diagnostic.field();
      if (!diagnostic.valid || diagnostic.offset != diagnostic.bytes.size()) return false;
#endif
    } else return false;
    recipe.operations.push_back(std::move(operation));
  }
  return reader.valid && reader.offset == reader.bytes.size();
}
void report(DiagnosticsEngine &diags, StringRef data) {
  Reader reader{data};
  auto id = reader.number();
  auto location = SourceLocation::getFromRawEncoding(reader.number());
  auto arguments = reader.number();
  std::vector<Bytes> strings;
  strings.reserve(arguments);
  auto builder = diags.Report(location, id);
  for (unsigned i = 0; i < arguments; ++i) {
    auto kind = reader.number();
    if (kind == DiagnosticsEngine::ak_std_string) builder.AddString(reader.field());
    else if (kind == DiagnosticsEngine::ak_c_string) {
      strings.push_back(reader.field()); builder << strings.back().c_str();
    } else if (kind == DiagnosticsEngine::ak_sint) builder << int32_t(reader.number());
    else builder << unsigned(reader.number());
  }
  auto ranges = reader.number();
  for (unsigned i = 0; i < ranges; ++i) {
    auto begin = SourceLocation::getFromRawEncoding(reader.number());
    auto end = SourceLocation::getFromRawEncoding(reader.number());
    builder << CharSourceRange(SourceRange(begin, end), reader.number() != 0);
  }
#ifdef RGEC_RESIDUAL_BUILD
  builder << AddFlagValue(reader.field());
#endif
}
} // namespace

#ifdef RGEC_RESIDUAL_BUILD
#include "clang_residual_backend.h"
#endif

bool apply_recipe(Recipe &recipe, llvm::Module *module, SourceManager &sm,
                  DiagnosticsEngine &diags, const CodeGenOptions &codegen,
                  raw_pwrite_stream *output) {
  Bytes query = "RGECQ1"; field(query, recipe.key);
  if (send(query)) {
    Recipe supplied;
    bool accepted = decode(receive(), supplied) && supplied.reusable;
#ifdef RGEC_RESIDUAL_BUILD
    if (!supplied.computationKey.empty())
      accepted = accepted && recipe.computationScopeAllowed &&
                 supplied.computationKey == residual_projection(recipe.key) &&
                 parametric_effect_profile(supplied);
    else
#endif
      accepted = accepted && supplied.key == recipe.key;
    if (accepted) {
      bool valid = true;
      unsigned next = sm.getNextLocalOffset();
      for (auto &frame : supplied.frames) {
        if (frame.offset != next || frame.characteristic > SrcMgr::C_ExternCSystem) valid = false;
        next += frame.data.size() + 1;
      }
#ifdef RGEC_RESIDUAL_BUILD
      std::vector<std::unique_ptr<GeneratedStackDiagnostic>> generated(supplied.operations.size());
      for (unsigned i = 0; i < supplied.operations.size(); ++i) {
        auto &operation = supplied.operations[i];
        if (operation.kind == 5 && !residual_diagnostic_valid(*module, operation.data)) valid = false;
        if (operation.kind == 8 && !suppressed_remark_valid(codegen, operation.data)) valid = false;
        if (operation.kind == 9 && !residual_remark_valid(*module, operation.data)) valid = false;
        if (operation.kind == 6) {
          generated[i] = generated_diagnostic(*module, operation.data);
          if (!generated[i]) valid = false;
        }
      }
#endif
      if (valid) {
        for (auto &frame : supplied.frames)
          sm.createFileID(MemoryBuffer::getMemBufferCopy(frame.data, frame.name),
              SrcMgr::CharacteristicKind(frame.characteristic));
        for (unsigned i = 0; i < supplied.operations.size(); ++i) {
          auto &operation = supplied.operations[i];
          if (operation.kind == 0) output->write(operation.data.data(), operation.data.size());
          else if (operation.kind == 1) output->pwrite(operation.data.data(), operation.data.size(), operation.offset);
#ifdef RGEC_RESIDUAL_BUILD
          else if (operation.kind == 5) apply_residual_diagnostic(*module, operation.data);
          else if (operation.kind == 6) apply_generated_diagnostic(*module, *generated[i]);
          else if (operation.kind == 8) continue;
          else if (operation.kind == 9) apply_residual_remark(*module, operation.data);
#endif
          else report(diags, operation.data);
        }
        send("RGECH1");
        return true;
      }
    }
  }
  return false;
}

#define BACKEND_PARAMETERS DiagnosticsEngine &diags, const HeaderSearchOptions &headers, \
  const CodeGenOptions &codegen, const clang::TargetOptions &target, const LangOptions &language, \
  const DataLayout &layout, llvm::Module *module, BackendAction action, \
  std::unique_ptr<raw_pwrite_stream> output
#define BACKEND_ARGUMENTS diags, headers, codegen, target, language, layout, module, action
void real_backend(BACKEND_PARAMETERS) asm("__real_" RGEC_BACKEND_SYMBOL);
void wrapped_backend(BACKEND_PARAMETERS) asm("__wrap_" RGEC_BACKEND_SYMBOL);
#ifdef RGEC_READ_BUILD
#include "clang_backend_read_state.h"
#endif
void wrapped_backend(BACKEND_PARAMETERS) {
#ifdef RGEC_RESIDUAL_BUILD
  if (residual_module) {
    module = residual_module.get();
    if (state(*module, diags.getSourceManager()) != residual_key) {
      errs() << "Captured residual state was not reproduced exactly\n";
      diags.Report(diag::err_fe_error_backend) << "residual context mismatch";
      return;
    }
  }
#endif
  auto mode = std::getenv("RGEC_BACKEND_MODE");
  auto &sm = diags.getSourceManager();
#ifdef RGEC_RESIDUAL_BUILD
  // Symbol maps are backend reads absent from the captured IR/source state.
  // Optimization records and GCOV notes bypass the captured main stream.
  // Preserve those real dependencies/effects before any shared lookup.
  if (mode && (native_report_options() || module->getContext().getDiagnosticsOutputFile() ||
#ifndef RGEC_READ_BUILD
               !codegen.RewriteMapFiles.empty() ||
#else
               codegen.ExperimentalNewPassManager ||
#endif
               (codegen.EmitGcovNotes && !codegen.DisableGCov && !codegen.DisableLLVMPasses))) {
    send("RGECP1");
    real_backend(BACKEND_ARGUMENTS, std::move(output)); return;
  }
#endif
  if (!mode || action != Backend_EmitObj || !candidate(*module, sm)) {
    if (mode) send("RGECP1");
    real_backend(BACKEND_ARGUMENTS, std::move(output)); return;
  }
#ifdef RGEC_READ_BUILD
  // Every supported legacy request executes native setup before admission.
  // The same read/callback rejection state now covers unmapped requests.
  read_closed_backend(BACKEND_ARGUMENTS, std::move(output)); return;
#else
  Recipe recipe;
  recipe.key = state(*module, sm);
#ifdef RGEC_RESIDUAL_BUILD
  if (parametric_producer && recipe.computationScopeAllowed)
    recipe.computationKey = residual_projection(recipe.key);
#endif
  if (StringRef(mode) == "replay") {
    if (apply_recipe(recipe, module, sm, diags, codegen, output.get())) return;
    // Invalid or differently bound recipes do not supply object bytes.
    // This laboratory fallback is native; a future host must hide its capacity.
    send("RGECF1");
    real_backend(BACKEND_ARGUMENTS, std::move(output)); return;
  }
  unsigned initial = sm.local_sloc_entry_size();
  auto nativeClient = diags.takeClient();
  RecordingDiagnostics diagnostics(*nativeClient, recipe);
  diags.setClient(&diagnostics, false);
#ifdef RGEC_RESIDUAL_BUILD
  auto &context = module->getContext();
  auto *bridge = new ResidualDiagnosticHandler(context.getDiagnosticHandler(), recipe, codegen, *module);
  context.setDiagnosticHandler(std::unique_ptr<llvm::DiagnosticHandler>(bridge));
#endif
  real_backend(BACKEND_ARGUMENTS, llvm::make_unique<RecordingStream>(std::move(output), recipe));
#ifdef RGEC_RESIDUAL_BUILD
  auto recordedHandler = context.getDiagnosticHandler();
  context.setDiagnosticHandler(bridge->takeNative());
#endif
  diags.setClient(nativeClient.release(), true);
  for (unsigned i = initial; i < sm.local_sloc_entry_size(); ++i) {
    auto &entry = sm.getLocalSLocEntry(i);
    if (!entry.isFile() || entry.getFile().getIncludeLoc().isValid()) { recipe.reusable = false; continue; }
    auto location = SourceLocation::getFromRawEncoding(entry.getOffset());
    auto file = sm.getFileID(location);
    if (sm.getFileEntryForID(file)) recipe.reusable = false;
    recipe.frames.push_back({entry.getOffset(), unsigned(entry.getFile().getFileCharacteristic()),
                            sm.getBufferName(location).str(), sm.getBufferData(file).str()});
  }
#ifdef RGEC_RESIDUAL_BUILD
  if (!recipe.computationKey.empty() && !parametric_effect_profile(recipe)) recipe.computationKey.clear();
#endif
  send(encode(recipe));
#endif
}

int main(int argc, const char **argv) {
  if (std::getenv("RGEC_BACKEND_MODE") && argc > 1 && StringRef(argv[1]) == "-cc1") {
    struct rlimit limit;
    // Replay can fail inside a different native pretty-stack-trace scope.
    // Finite file-size limits therefore select the original cc1 before lookup.
    if (::getrlimit(RLIMIT_FSIZE, &limit) != 0 || limit.rlim_cur != RLIM_INFINITY) {
      send("RGECP1");
      std::vector<char *> nativeArguments;
      nativeArguments.push_back(const_cast<char *>("/usr/local/bin/clang"));
      for (int i = 1; i < argc; ++i) nativeArguments.push_back(const_cast<char *>(argv[i]));
      nativeArguments.push_back(nullptr);
      ::execv(nativeArguments.front(), nativeArguments.data());
      std::perror("native compiler exec");
      return 1;
    }
  }
  llvm::InitLLVM nativeEnvironment(argc, argv);
#ifdef RGEC_RESIDUAL_BUILD
  if (argc == 2 && (StringRef(argv[1]) == "--rgec-produce-residual" ||
                   StringRef(argv[1]) == "--rgec-produce-parametric")) {
    parametric_producer = StringRef(argv[1]) == "--rgec-produce-parametric";
    return residual_main();
  }
#endif
  if (argc > 1 && StringRef(argv[1]) == "-cc1") { --argc; ++argv; }
  InitializeAllTargets(); InitializeAllTargetMCs();
  InitializeAllAsmPrinters(); InitializeAllAsmParsers();
  auto ownedCompiler = llvm::make_unique<CompilerInstance>();
  auto &compiler = *ownedCompiler;
  IntrusiveRefCntPtr<DiagnosticIDs> ids(new DiagnosticIDs());
  IntrusiveRefCntPtr<DiagnosticOptions> options(new DiagnosticOptions());
  auto *buffer = new TextDiagnosticBuffer;
  DiagnosticsEngine parsing(ids, options, buffer);
  for (int i = 1; i < argc; ++i) invocation.emplace_back(argv[i]);
  bool parsed = CompilerInvocation::CreateFromArgs(compiler.getInvocation(), argv + 1, argv + argc, parsing);
  set_native_finish_reports(compiler);
  compiler.createDiagnostics();
  llvm::install_fatal_error_handler(backend_fatal, &compiler.getDiagnostics());
  buffer->FlushDiagnostics(compiler.getDiagnostics());
  bool success = parsed && ExecuteCompilerInvocation(&compiler);
  // Native cc1 prints still-live pass timers before uninstalling its handler.
  llvm::TimerGroup::printAll(llvm::errs());
  llvm::remove_fatal_error_handler();
  if (compiler.getFrontendOpts().DisableFree) BuryPointer(std::move(ownedCompiler));
  return success ? 0 : 1;
}
