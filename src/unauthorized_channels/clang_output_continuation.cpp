// Native output-continuation feasibility probe, not a cache admission action.
// Object bytes on stdin must come from a separate genuine native compilation.
#include "clang/AST/ASTConsumer.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendPluginRegistry.h"
#include "llvm/Support/raw_ostream.h"
#include <memory>
#include <unistd.h>

using namespace clang;

namespace {
class OutputConsumer : public ASTConsumer {
  CompilerInstance &compiler;
  std::unique_ptr<llvm::raw_pwrite_stream> output;
public:
  OutputConsumer(CompilerInstance &compiler,
                 std::unique_ptr<llvm::raw_pwrite_stream> output)
      : compiler(compiler), output(std::move(output)) {}
  void HandleTranslationUnit(ASTContext &) override {
    if (compiler.getDiagnostics().hasErrorOccurred()) return;
    char buffer[65536];
    ssize_t count;
    while ((count = ::read(STDIN_FILENO, buffer, sizeof(buffer))) > 0)
      output->write(buffer, count);
    if (count < 0)
      compiler.getDiagnostics().Report(compiler.getDiagnostics().getCustomDiagID(
          DiagnosticsEngine::Error, "native payload transport failed"));
  }
};

class OutputAction : public PluginASTAction {
  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &compiler,
                                                llvm::StringRef input) override {
    auto output = compiler.createDefaultOutputFile(true, input, "o");
    if (!output) return nullptr;
    return llvm::make_unique<OutputConsumer>(compiler, std::move(output));
  }
  bool ParseArgs(const CompilerInstance &, const std::vector<std::string> &args) override {
    return args.empty();
  }
};

FrontendPluginRegistry::Add<OutputAction> registered(
    "rgec-output-continuation", "probe native recipient output continuation");
} // namespace
