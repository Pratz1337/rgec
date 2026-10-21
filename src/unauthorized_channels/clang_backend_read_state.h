// Experimental native map-read cutpoint. This is not general backend closure.
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/Utils/SymbolRewriter.h"

namespace {
struct NativeRead {
  Bytes path, identifier, contents;
  uint64_t size, terminated, volatileFile;
};
std::vector<NativeRead> imported_reads, observed_reads;
unsigned imported_read_cursor = 0;
const std::string *active_map_path = nullptr;
struct ReadCutpoint {
  Recipe &recipe;
  llvm::Module *module;
  SourceManager &sm;
  DiagnosticsEngine &diags;
  const CodeGenOptions &codegen;
  raw_pwrite_stream *output;
  StringRef mode;
  bool entered = false, hit = false, privatePath = false;
};
ReadCutpoint *read_cutpoint = nullptr;

bool read_fields(Reader &input, std::vector<NativeRead> *reads = nullptr) {
  if (input.offset == input.bytes.size()) return true;
  if (input.bytes.substr(input.offset, 6) != "RGECR1") return false;
  input.offset += 6;
  auto count = input.number();
  if (!input.valid || count == 0 || count > 10000) return false;
  for (unsigned i = 0; i < count; ++i) {
    NativeRead value;
    value.path = input.field(); value.size = input.number();
    value.terminated = input.number(); value.volatileFile = input.number();
    value.identifier = input.field(); value.contents = input.field();
    if (!input.valid || value.terminated > 1 || value.volatileFile > 1) return false;
    if (reads) reads->push_back(std::move(value));
  }
  return input.valid && input.offset == input.bytes.size();
}
bool project_native_read_state(Reader &input) { return read_fields(input); }
bool restore_native_read_state(Reader &input) { return read_fields(input, &imported_reads); }
void append_native_read_state(Bytes &out) {
  auto &reads = observed_reads.empty() ? imported_reads : observed_reads;
  if (reads.empty()) return;
  out += "RGECR1"; number(out, reads.size());
  for (auto &value : reads) {
    field(out, value.path); number(out, value.size);
    number(out, value.terminated); number(out, value.volatileFile);
    field(out, value.identifier); field(out, value.contents);
  }
}
} // namespace

using NativeMapParser = llvm::SymbolRewriter::RewriteMapParser;
using NativeDescriptors = llvm::SymbolRewriter::RewriteDescriptorList;
bool real_map_parse(NativeMapParser *, const std::string &, NativeDescriptors *) asm("__real_" RGEC_MAP_PARSE_SYMBOL);
bool wrapped_map_parse(NativeMapParser *, const std::string &, NativeDescriptors *) asm("__wrap_" RGEC_MAP_PARSE_SYMBOL);
bool wrapped_map_parse(NativeMapParser *parser, const std::string &path, NativeDescriptors *descriptors) {
  auto previous = active_map_path;
  if (read_cutpoint) active_map_path = &path;
  bool result = real_map_parse(parser, path, descriptors);
  active_map_path = previous;
  return result;
}

using NativeBuffer = ErrorOr<std::unique_ptr<MemoryBuffer>>;
NativeBuffer real_read_file(const Twine &, int64_t, bool, bool) asm("__real_" RGEC_READ_FILE_SYMBOL);
NativeBuffer wrapped_read_file(const Twine &, int64_t, bool, bool) asm("__wrap_" RGEC_READ_FILE_SYMBOL);
NativeBuffer wrapped_read_file(const Twine &path, int64_t size, bool terminated, bool volatileFile) {
  if (!read_cutpoint) return real_read_file(path, size, terminated, volatileFile);
  auto name = path.str();
  if (!active_map_path || name != *active_map_path || read_cutpoint->entered) {
    read_cutpoint->recipe.reusable = false;
    if (!read_cutpoint->entered) read_cutpoint->privatePath = true;
    return real_read_file(path, size, terminated, volatileFile);
  }
  NativeBuffer result = [&]() -> NativeBuffer {
    if (!imported_reads.empty()) {
      if (imported_read_cursor < imported_reads.size()) {
        auto &value = imported_reads[imported_read_cursor];
        if (value.path == name && value.size == uint64_t(size) &&
            value.terminated == terminated && value.volatileFile == volatileFile) {
          ++imported_read_cursor;
          return MemoryBuffer::getMemBufferCopy(value.contents, value.identifier);
        }
      }
      read_cutpoint->recipe.reusable = false;
      read_cutpoint->privatePath = true;
    }
    return real_read_file(path, size, terminated, volatileFile);
  }();
  if (result) observed_reads.push_back({name, (*result)->getBufferIdentifier().str(),
      (*result)->getBuffer().str(), uint64_t(size), uint64_t(terminated), uint64_t(volatileFile)});
  return result;
}

bool real_fp_init(legacy::FunctionPassManager *) asm("__real_" RGEC_FP_INIT_SYMBOL);
bool wrapped_fp_init(legacy::FunctionPassManager *) asm("__wrap_" RGEC_FP_INIT_SYMBOL);
bool wrapped_fp_init(legacy::FunctionPassManager *manager) {
  if (read_cutpoint && !read_cutpoint->entered) {
    auto &cut = *read_cutpoint;
    cut.entered = true;
    if (observed_reads.size() != cut.codegen.RewriteMapFiles.size() ||
        (!imported_reads.empty() && imported_read_cursor != imported_reads.size()) ||
        !cut.recipe.operations.empty() || !cut.recipe.reusable ||
        !cut.recipe.computationScopeAllowed) cut.privatePath = true;
    if (cut.privatePath) {
      send("RGECP1");
    } else {
      cut.recipe.key = state(*cut.module, cut.sm);
      if (parametric_producer && cut.recipe.computationScopeAllowed)
        cut.recipe.computationKey = residual_projection(cut.recipe.key);
      if (cut.mode == "replay") {
        cut.hit = apply_recipe(cut.recipe, cut.module, cut.sm, cut.diags, cut.codegen, cut.output);
        if (!cut.hit) send("RGECF1");
      }
    }
  }
  return read_cutpoint && read_cutpoint->hit ? false : real_fp_init(manager);
}
bool real_fp_run(legacy::FunctionPassManager *, llvm::Function &) asm("__real_" RGEC_FP_RUN_SYMBOL);
bool wrapped_fp_run(legacy::FunctionPassManager *, llvm::Function &) asm("__wrap_" RGEC_FP_RUN_SYMBOL);
bool wrapped_fp_run(legacy::FunctionPassManager *manager, llvm::Function &function) {
  return read_cutpoint && read_cutpoint->hit ? false : real_fp_run(manager, function);
}
bool real_fp_end(legacy::FunctionPassManager *) asm("__real_" RGEC_FP_END_SYMBOL);
bool wrapped_fp_end(legacy::FunctionPassManager *) asm("__wrap_" RGEC_FP_END_SYMBOL);
bool wrapped_fp_end(legacy::FunctionPassManager *manager) {
  return read_cutpoint && read_cutpoint->hit ? false : real_fp_end(manager);
}
bool real_pm_run(legacy::PassManager *, llvm::Module &) asm("__real_" RGEC_PM_RUN_SYMBOL);
bool wrapped_pm_run(legacy::PassManager *, llvm::Module &) asm("__wrap_" RGEC_PM_RUN_SYMBOL);
bool wrapped_pm_run(legacy::PassManager *manager, llvm::Module &module) {
  return read_cutpoint && read_cutpoint->hit ? false : real_pm_run(manager, module);
}

void read_closed_backend(BACKEND_PARAMETERS) {
  auto &sm = diags.getSourceManager();
  Recipe recipe;
  unsigned initial = sm.local_sloc_entry_size();
  auto nativeClient = diags.takeClient();
  RecordingDiagnostics diagnostics(*nativeClient, recipe);
  diags.setClient(&diagnostics, false);
  auto &context = module->getContext();
  auto *bridge = new ResidualDiagnosticHandler(context.getDiagnosticHandler(), recipe, codegen, *module);
  context.setDiagnosticHandler(std::unique_ptr<llvm::DiagnosticHandler>(bridge));
  auto recorder = llvm::make_unique<RecordingStream>(std::move(output), recipe);
  ReadCutpoint cut{recipe, module, sm, diags, codegen, recorder.get(), std::getenv("RGEC_BACKEND_MODE")};
  read_cutpoint = &cut;
  real_backend(BACKEND_ARGUMENTS, std::move(recorder));
  read_cutpoint = nullptr;
  auto recordedHandler = context.getDiagnosticHandler();
  context.setDiagnosticHandler(bridge->takeNative());
  diags.setClient(nativeClient.release(), true);
  if (!cut.entered) send("RGECP1");
  if (cut.privatePath || !cut.entered || cut.mode == "replay") return;
  for (unsigned i = initial; i < sm.local_sloc_entry_size(); ++i) {
    auto &entry = sm.getLocalSLocEntry(i);
    if (!entry.isFile() || entry.getFile().getIncludeLoc().isValid()) { recipe.reusable = false; continue; }
    auto location = SourceLocation::getFromRawEncoding(entry.getOffset());
    auto file = sm.getFileID(location);
    if (sm.getFileEntryForID(file)) recipe.reusable = false;
    recipe.frames.push_back({entry.getOffset(), unsigned(entry.getFile().getFileCharacteristic()),
                            sm.getBufferName(location).str(), sm.getBufferData(file).str()});
  }
  if (!recipe.computationKey.empty() && !parametric_effect_profile(recipe)) recipe.computationKey.clear();
  send(encode(recipe));
}
