// Experimental reconstruction of a genuine native backend request. The native
// BackendConsumer supplies its handlers; the captured module supplies the work.
// AST declaration lookup and complete diagnostic policy are not reconstructed.
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/ASTContext.h"
#include "clang/Basic/FileManager.h"
#include "clang/Basic/SourceManagerInternals.h"
#include "clang/Basic/TargetInfo.h"
#include "clang/CodeGen/CodeGenAction.h"
#include "clang/Lex/Preprocessor.h"
#include "llvm/Bitcode/BitcodeReader.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/DiagnosticInfo.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/ValueSymbolTable.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include <set>

namespace {
StringRef native_remark_name(const llvm::DiagnosticInfoOptimizationBase &);
// Stack-size data is computed remotely; its native Clang diagnostic remains a
// recipient operation, where the original AST declaration map still exists.
class ResidualDiagnosticHandler : public llvm::DiagnosticHandler {
  std::unique_ptr<llvm::DiagnosticHandler> native;
  Recipe &recipe;
  const CodeGenOptions &codegen;
  std::set<Bytes> prefixFunctions;
public:
  ResidualDiagnosticHandler(std::unique_ptr<llvm::DiagnosticHandler> native, Recipe &recipe,
                            const CodeGenOptions &codegen,
                            llvm::Module &module)
      : native(std::move(native)), recipe(recipe), codegen(codegen) {
    for (auto &function : module) prefixFunctions.insert(function.getName().str());
  }
  bool handleDiagnostics(const llvm::DiagnosticInfo &info) override {
    if (info.getKind() == llvm::DK_StackSize && info.getSeverity() == llvm::DS_Warning) {
      auto &stack = cast<llvm::DiagnosticInfoStackSize>(info);
      bool prefix = prefixFunctions.count(stack.getFunction().getName().str());
      Bytes data; field(data, stack.getFunction().getName()); number(data, stack.getStackSize());
      number(data, stack.getStackLimit());
      if (!prefix) {
        // The native stack renderer reads the function's name, not its body.
        // Keep the genuine diagnosed definition and any block-address owners;
        // native CloneModule replaces other definitions by external references.
        auto &module = *stack.getFunction().getParent();
        field(data, module.getModuleIdentifier());
        ValueToValueMapTy values;
        auto snapshot = CloneModule(module, values, [&](const GlobalValue *value) {
          auto *function = dyn_cast<Function>(value);
          if (!function) return false;
          if (function == &stack.getFunction()) return true;
          for (auto *user : function->users())
            if (isa<BlockAddress>(user)) return true;
          return false;
        });
        SmallVector<char, 0> bitcode; raw_svector_ostream stream(bitcode);
        WriteBitcodeToFile(*snapshot, stream, true);
        field(data, StringRef(bitcode.data(), bitcode.size()));
      }
      recipe.operations.push_back({prefix ? 5U : 6U, std::move(data), 0});
      recipe.nativeDiagnosticContinuation = true;
      bool handled = native->handleDiagnostics(info);
      recipe.nativeDiagnosticContinuation = false;
      return handled;
    }
    // These native handlers return without rendering when the corresponding
    // effective remark option is absent. Record that precondition explicitly;
    // zero emitted diagnostics alone is not an admission witness.
    unsigned silent = 3;
    if (info.getSeverity() == llvm::DS_Remark) {
      switch (info.getKind()) {
      case llvm::DK_OptimizationRemark:
      case llvm::DK_MachineOptimizationRemark:
        if (!codegen.OptimizationRemarkPattern) silent = 0;
        break;
      case llvm::DK_OptimizationRemarkMissed:
      case llvm::DK_MachineOptimizationRemarkMissed:
        if (!codegen.OptimizationRemarkMissedPattern) silent = 1;
        break;
      case llvm::DK_OptimizationRemarkAnalysis:
        if (!codegen.OptimizationRemarkAnalysisPattern &&
            !cast<llvm::OptimizationRemarkAnalysis>(info).shouldAlwaysPrint()) silent = 2;
        break;
      case llvm::DK_MachineOptimizationRemarkAnalysis:
        if (!codegen.OptimizationRemarkAnalysisPattern) silent = 2;
        break;
      default: break;
      }
    }
    if (silent < 3) {
      Bytes data; number(data, silent);
      recipe.operations.push_back({8, std::move(data), 0});
      return native->handleDiagnostics(info);
    }
    // Location-free passed remarks need the recipient's genuine declaration
    // lookup. Keep the native request fields, not a producer-rendered location.
    if (info.getKind() == llvm::DK_OptimizationRemark &&
        info.getSeverity() == llvm::DS_Remark) {
      auto &remark = cast<llvm::OptimizationRemark>(info);
      if (!remark.isLocationAvailable() && !remark.isVerbose() && !remark.getHotness() &&
          prefixFunctions.count(remark.getFunction().getName().str())) {
        Bytes data; field(data, remark.getFunction().getName());
        field(data, remark.getPassName()); field(data, native_remark_name(remark));
        field(data, remark.getMsg());
        recipe.operations.push_back({9, std::move(data), 0});
        recipe.nativeDiagnosticContinuation = true;
        bool handled = native->handleDiagnostics(info);
        recipe.nativeDiagnosticContinuation = false;
        return handled;
      }
    }
    // Scope the incoming callback, even when the native handler suppresses
    // emission and leaves no diagnostic operation for the recorder to inspect.
    recipe.computationScopeAllowed = false;
    recipe.computationKey.clear();
    return native->handleDiagnostics(info);
  }
  bool isAnalysisRemarkEnabled(StringRef pass) const override { return native->isAnalysisRemarkEnabled(pass); }
  bool isMissedOptRemarkEnabled(StringRef pass) const override { return native->isMissedOptRemarkEnabled(pass); }
  bool isPassedOptRemarkEnabled(StringRef pass) const override { return native->isPassedOptRemarkEnabled(pass); }
  bool isAnyRemarkEnabled() const override { return native->isAnyRemarkEnabled(); }
  std::unique_ptr<llvm::DiagnosticHandler> takeNative() { return std::move(native); }
};

bool suppressed_remark_valid(const CodeGenOptions &codegen, StringRef data) {
  Reader input{data}; auto kind = input.number();
  if (!input.valid || input.offset != input.bytes.size()) return false;
  return (kind == 0 && !codegen.OptimizationRemarkPattern) ||
         (kind == 1 && !codegen.OptimizationRemarkMissedPattern) ||
         (kind == 2 && !codegen.OptimizationRemarkAnalysisPattern);
}

bool residual_remark_valid(llvm::Module &module, StringRef data) {
  Reader input{data}; auto name = input.field(); input.field(); input.field(); input.field();
  auto *function = module.getFunction(name);
  return input.valid && input.offset == input.bytes.size() && function && !function->empty();
}
void apply_residual_remark(llvm::Module &module, StringRef data) {
  Reader input{data}; auto name = input.field(), pass = input.field();
  auto label = input.field(), message = input.field();
  auto *function = module.getFunction(name);
  llvm::OptimizationRemark remark(pass.c_str(), label, llvm::DiagnosticLocation(), &function->front());
  remark << StringRef(message);
  module.getContext().diagnose(remark);
}

bool residual_diagnostic_valid(llvm::Module &module, StringRef data) {
  Reader input{data}; auto name = input.field(); input.number(); input.number();
  return input.valid && input.offset == input.bytes.size() && module.getFunction(name);
}
void apply_residual_diagnostic(llvm::Module &module, StringRef data) {
  Reader input{data}; auto name = input.field(); auto size = input.number(), limit = input.number();
  llvm::DiagnosticInfoStackSize diagnostic(*module.getFunction(name), size, llvm::DS_Warning, limit);
  module.getContext().diagnose(diagnostic);
}

struct GeneratedStackDiagnostic {
  LLVMContext context;
  std::unique_ptr<llvm::Module> module;
  Bytes name;
  uint64_t size, limit;
};
std::unique_ptr<GeneratedStackDiagnostic> generated_diagnostic(llvm::Module &prefix, StringRef data) {
  Reader input{data};
  auto result = llvm::make_unique<GeneratedStackDiagnostic>();
  result->name = input.field(); result->size = input.number();
  result->limit = input.number();
  auto identifier = input.field(), bitcode = input.field();
  if (!input.valid || input.offset != input.bytes.size() || prefix.getFunction(result->name)) return {};
  auto parsed = parseBitcodeFile(MemoryBufferRef(bitcode, identifier), result->context);
  if (!parsed) { consumeError(parsed.takeError()); return {}; }
  result->module = std::move(*parsed);
  result->module->setModuleIdentifier(identifier);
  auto *function = result->module->getFunction(result->name);
  if (!function || function->isDeclaration()) return {};
  return result;
}
void apply_generated_diagnostic(llvm::Module &recipient, const GeneratedStackDiagnostic &generated) {
  llvm::DiagnosticInfoStackSize diagnostic(*generated.module->getFunction(generated.name),
                                         generated.size, llvm::DS_Warning, generated.limit);
  recipient.getContext().diagnose(diagnostic);
}

Bytes residual_key;
Bytes residual_bitcode;
std::unique_ptr<llvm::Module> residual_module;
bool parametric_producer = false;

// Experimental computation identity. Native source/diagnostic context remains
// request-local. This projection is not a complete hidden-input certificate.
Bytes residual_projection(StringRef full) {
  Reader input{full}; Bytes core = "RGECK1";
  auto arguments = input.number();
  if (!input.valid || arguments > 10000) return {};
  number(core, arguments);
  for (unsigned i = 0; i < arguments; ++i) field(core, input.field());
  field(core, input.field());
  auto count = input.number(); input.number();
  if (!input.valid || count < 2 || count > 1000000) return {};
  std::vector<bool> files;
  for (unsigned i = 1; i < count; ++i) {
    input.number(); bool file = input.number() != 0; files.push_back(file);
    input.number(); input.number();
    if (file) { input.field(); input.field(); }
    else { input.number(); input.number(); }
  }
  if (!input.valid || input.bytes.substr(input.offset, 6) != "RGECS3") return {};
  input.offset += 6;
  field(core, input.field()); input.number();
  for (bool file : files) {
    input.number();
    if (file) { input.number(); input.number(); }
  }
  if (input.number()) {
    auto names = input.number();
    if (!input.valid || names > 1000000) return {};
    for (unsigned i = 0; i < names; ++i) input.field();
    auto entries = input.number();
    if (!input.valid || entries > count) return {};
    for (unsigned i = 0; i < entries; ++i) {
      input.number(); auto lines = input.number();
      if (!input.valid || lines > 1000000) return {};
      for (unsigned j = 0; j < lines * 5; ++j) input.number();
    }
  }
  auto tail = input.offset;
  input.number(); input.number(); auto functions = input.number();
  if (!input.valid || functions > 1000000) return {};
  for (unsigned i = 0; i < functions; ++i) {
    input.field(); if (input.number()) input.number();
  }
#ifdef RGEC_READ_BUILD
  if (!project_native_read_state(input)) return {};
#endif
  if (!input.valid || input.offset != input.bytes.size()) return {};
  core.append(full.data() + tail, full.size() - tail);
  return core;
}

bool parametric_effect_profile(const Recipe &recipe) {
  if (!recipe.frames.empty()) return false;
  for (auto &operation : recipe.operations) {
    if (operation.kind != 0 && operation.kind != 1 && operation.kind != 5 &&
        operation.kind != 6 && operation.kind != 8 && operation.kind != 9)
      return false;
  }
  return true;
}

// The authentic LLVM 7 header declares this counter, but bitcode omits it.
// Explicit instantiation uses the C++ access exception to obtain its real
// member pointer; no guessed object layout or compiler-library patch is used.
struct NativeNameCounter {
  using type = uint32_t ValueSymbolTable::*;
  friend type native_member(NativeNameCounter);
};
template <class Tag, typename Tag::type Member> struct NativeMember {
  friend typename Tag::type native_member(Tag) { return Member; }
};
struct NativeRemarkName {
  using type = StringRef llvm::DiagnosticInfoOptimizationBase::*;
  friend type native_member(NativeRemarkName);
};
template struct NativeMember<NativeRemarkName, &llvm::DiagnosticInfoOptimizationBase::RemarkName>;
StringRef native_remark_name(const llvm::DiagnosticInfoOptimizationBase &remark) {
  return remark.*native_member(NativeRemarkName());
}
template struct NativeMember<NativeNameCounter, &ValueSymbolTable::LastUnique>;
uint32_t &name_counter(ValueSymbolTable &table) {
  return table.*native_member(NativeNameCounter());
}

StringRef residual_input_bitcode(llvm::Module &module) {
  return residual_module.get() == &module ? StringRef(residual_bitcode) : StringRef();
}

void append_residual_state(Bytes &out, llvm::Module &module, SourceManager &sm) {
  out += "RGECS3";
  field(out, module.getModuleIdentifier());
  number(out, sm.getLocForStartOfFile(sm.getMainFileID()).getRawEncoding());
  for (unsigned i = 1; i < sm.local_sloc_entry_size(); ++i) {
    auto &entry = sm.getLocalSLocEntry(i);
    if (entry.isFile()) {
      number(out, sm.getFileEntryForSLocEntry(entry) != nullptr);
      number(out, entry.getFile().hasLineDirectives());
      number(out, sm.getNumCreatedFIDsForFileID(sm.getFileID(
                             SourceLocation::getFromRawEncoding(entry.getOffset()))));
    } else {
      number(out, entry.getExpansion().isMacroArgExpansion());
    }
  }
  number(out, sm.hasLineTable());
  if (sm.hasLineTable()) {
    auto &table = sm.getLineTable();
    number(out, table.getNumFilenames());
    for (unsigned i = 0; i < table.getNumFilenames(); ++i)
      field(out, table.getFilename(i));
    number(out, std::distance(table.begin(), table.end()));
    for (auto &file : table) {
      number(out, sm.getLocForStartOfFile(file.first).getRawEncoding());
      number(out, file.second.size());
      for (auto &line : file.second) {
        number(out, line.FileOffset); number(out, line.LineNo);
        number(out, uint32_t(line.FilenameID)); number(out, line.FileKind);
        number(out, line.IncludeOffset);
      }
    }
  }
  number(out, module.getContext().shouldDiscardValueNames());
  number(out, name_counter(module.getValueSymbolTable()));
  number(out, module.size());
  for (auto &function : module) {
    field(out, function.getName());
    auto *symbols = function.getValueSymbolTable();
    number(out, symbols != nullptr);
    if (symbols) number(out, name_counter(*symbols));
  }
}

struct ResidualSource {
  unsigned offset, first, second, third = 0, createdFiles = 0;
  bool file, token = false, fileBacked = false, lineDirectives = false, macroArg = false;
  Bytes name, data;
};

class ResidualAction : public EmitObjAction {
public:
  explicit ResidualAction(LLVMContext &context) : EmitObjAction(&context) {}
  using CodeGenAction::CreateASTConsumer;
};

int residual_main() {
  residual_key = receive();
  Reader input{residual_key};
  auto argc = input.number();
  if (!input.valid || argc > 10000) return 2;
  for (unsigned i = 0; i < argc; ++i) invocation.push_back(input.field());
  Bytes bitcode = input.field();
  auto count = input.number(), next = input.number();
  if (!input.valid || count < 2 || count > 1000000) return 2;
  std::vector<ResidualSource> sources;
  for (unsigned i = 1; i < count; ++i) {
    ResidualSource entry;
    entry.offset = input.number(); entry.file = input.number() != 0;
    entry.first = input.number(); entry.second = input.number();
    if (entry.file) { entry.name = input.field(); entry.data = input.field(); }
    else { entry.third = input.number(); entry.token = input.number() != 0; }
    sources.push_back(std::move(entry));
  }
  if (!input.valid || input.bytes.substr(input.offset, 6) != "RGECS3") return 2;
  input.offset += 6;
  auto identifier = input.field();
  auto mainOffset = input.number();
  for (auto &entry : sources) {
    if (entry.file) {
      entry.fileBacked = input.number() != 0;
      entry.lineDirectives = input.number() != 0;
      entry.createdFiles = input.number();
    } else entry.macroArg = input.number() != 0;
  }
  InitializeAllTargets(); InitializeAllTargetMCs();
  InitializeAllAsmPrinters(); InitializeAllAsmParsers();
  CompilerInstance compiler;
  IntrusiveRefCntPtr<DiagnosticIDs> ids(new DiagnosticIDs());
  IntrusiveRefCntPtr<DiagnosticOptions> options(new DiagnosticOptions());
  auto *buffer = new TextDiagnosticBuffer;
  DiagnosticsEngine parsing(ids, options, buffer);
  std::vector<const char *> arguments;
  for (auto &argument : invocation) arguments.push_back(argument.c_str());
  if (!CompilerInvocation::CreateFromArgs(compiler.getInvocation(), arguments.data(),
        arguments.data() + arguments.size(), parsing)) return 2;
  set_native_finish_reports(compiler);
  compiler.createDiagnostics();
  buffer->FlushDiagnostics(compiler.getDiagnostics());
  if (!compiler.getFrontendOpts().LLVMArgs.empty()) {
    std::vector<const char *> llvmArguments{"clang (LLVM option parsing)"};
    for (auto &argument : compiler.getFrontendOpts().LLVMArgs)
      llvmArguments.push_back(argument.c_str());
    llvm::cl::ParseCommandLineOptions(llvmArguments.size(), llvmArguments.data());
  }
  compiler.setTarget(TargetInfo::CreateTargetInfo(compiler.getDiagnostics(),
                                               compiler.getInvocation().TargetOpts));
  if (!compiler.hasTarget()) return 2;
  compiler.getTarget().adjust(compiler.getLangOpts());
  compiler.getTarget().adjustTargetOptions(compiler.getCodeGenOpts(), compiler.getTargetOpts());
  compiler.createFileManager(); compiler.createSourceManager(compiler.getFileManager());
  compiler.createPreprocessor(TU_Complete); compiler.createASTContext();
  auto &sm = compiler.getSourceManager();
  sm.clearIDTables();
  auto loc = [](unsigned raw) { return SourceLocation::getFromRawEncoding(raw); };
  for (unsigned i = 0; i < sources.size(); ++i) {
    auto &entry = sources[i];
    if (sm.getNextLocalOffset() != entry.offset) return 2;
    if (entry.file) {
      auto memory = MemoryBuffer::getMemBufferCopy(entry.data, entry.name);
      FileID id;
      auto kind = SrcMgr::CharacteristicKind(entry.second);
      if (entry.fileBacked) {
        auto *file = compiler.getFileManager().getVirtualFile(entry.name, entry.data.size(), 0);
        sm.overrideFileContents(file, std::move(memory));
        id = sm.createFileID(file, loc(entry.first), kind);
      } else {
        id = sm.createFileID(std::move(memory), kind, 0, 0, loc(entry.first));
      }
      if (entry.lineDirectives)
        const_cast<SrcMgr::FileInfo &>(sm.getSLocEntry(id).getFile()).setHasLineDirectives();
      sm.setNumCreatedFIDsForFileID(id, entry.createdFiles);
    } else {
      auto limit = i + 1 < sources.size() ? sources[i + 1].offset : next;
      if (limit <= entry.offset) return 2;
      auto length = limit - entry.offset - 1;
      if (entry.macroArg) sm.createMacroArgExpansionLoc(loc(entry.first), loc(entry.second), length);
      else sm.createExpansionLoc(loc(entry.first), loc(entry.second), loc(entry.third), length, entry.token);
    }
  }
  sm.setMainFileID(sm.getFileID(loc(mainOffset)));
  if (input.number()) {
    auto &table = sm.getLineTable(); table.clear();
    auto names = input.number();
    if (names > 1000000) return 2;
    for (unsigned i = 0; i < names; ++i)
      if (table.getLineTableFilenameID(input.field()) != i) return 2;
    auto files = input.number();
    if (files > count) return 2;
    for (unsigned i = 0; i < files; ++i) {
      auto offset = input.number(), lines = input.number();
      if (lines > 1000000) return 2;
      std::vector<LineEntry> entries;
      for (unsigned j = 0; j < lines; ++j) {
        auto position = input.number(), line = input.number(), filename = input.number();
        auto kind = input.number(), include = input.number();
        entries.push_back(LineEntry::get(position, line, int32_t(filename),
                         SrcMgr::CharacteristicKind(kind), include));
      }
      table.AddEntry(sm.getFileID(loc(offset)), entries);
    }
  }
  auto discardNames = input.number(), moduleCounter = input.number();
  auto functionCount = input.number();
  if (!input.valid || functionCount > 1000000) return 2;
  std::vector<std::pair<Bytes, uint64_t>> counters;
  for (unsigned i = 0; i < functionCount; ++i) {
    auto name = input.field();
    if (input.number()) counters.emplace_back(std::move(name), input.number());
  }
#ifdef RGEC_READ_BUILD
  if (!restore_native_read_state(input)) return 2;
#endif
  if (!input.valid || input.offset != input.bytes.size() || sm.getNextLocalOffset() != next) return 2;
  LLVMContext context;
  context.setDiscardValueNames(discardNames != 0);
  auto parsed = parseBitcodeFile(MemoryBufferRef(bitcode, identifier), context);
  if (!parsed) { logAllUnhandledErrors(parsed.takeError(), errs(), "captured bitcode: "); return 2; }
  residual_module = std::move(*parsed);
  residual_bitcode = bitcode;
  residual_module->setModuleIdentifier(identifier);
  name_counter(residual_module->getValueSymbolTable()) = moduleCounter;
  for (auto &counter : counters) {
    auto *function = residual_module->getFunction(counter.first);
    if (!function || !function->getValueSymbolTable()) { residual_module.reset(); return 2; }
    name_counter(*function->getValueSymbolTable()) = counter.second;
  }
  auto restored = state(*residual_module, sm);
  if (restored != residual_key) {
    Bytes difference = "RGECD2"; field(difference, restored); send(difference);
    errs() << "Captured residual state differs before native backend\n";
    residual_module.reset(); return 2;
  }
  setenv("RGEC_BACKEND_MODE", "record", 1);
  llvm::install_fatal_error_handler(backend_fatal, &compiler.getDiagnostics());
  ResidualAction action(context);
  auto consumer = action.CreateASTConsumer(compiler,
                         compiler.getFrontendOpts().Inputs[0].getFile());
  if (!consumer) { residual_module.reset(); llvm::remove_fatal_error_handler(); return 2; }
  compiler.getDiagnosticClient().BeginSourceFile(compiler.getLangOpts(), &compiler.getPreprocessor());
  consumer->Initialize(compiler.getASTContext());
  consumer->HandleTranslationUnit(compiler.getASTContext());
  compiler.getDiagnosticClient().EndSourceFile();
  bool failed = compiler.getDiagnostics().hasErrorOccurred();
  compiler.clearOutputFiles(failed);
  residual_module.reset();
  llvm::remove_fatal_error_handler();
  return failed ? 1 : 0;
}
} // namespace
