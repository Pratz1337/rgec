// Trusted admission observation; compiled against the native image's headers.
// This rejects known dependencies. It does not certify complete closure.
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendPluginRegistry.h"
#include "clang/Lex/MacroInfo.h"
#include "clang/Lex/PPCallbacks.h"
#include "clang/Lex/Preprocessor.h"
#include "llvm/Support/raw_ostream.h"
#include <memory>
#include <set>
#include <string>

using namespace clang;

namespace {
struct Observations {
  std::set<std::string> macroDependencies;
  bool assembly = false;
};

class MacroAudit : public PPCallbacks {
  Observations &seen;
public:
  explicit MacroAudit(Observations &seen) : seen(seen) {}
  void MacroExpands(const Token &token, const MacroDefinition &definition,
                    SourceRange, const MacroArgs *) override {
    if (!definition.getMacroInfo()->isBuiltinMacro()) return;
    auto name = token.getIdentifierInfo()->getName();
    if (name == "__TIME__" || name == "__DATE__" || name == "__TIMESTAMP__" ||
        name == "__COUNTER__" || name == "__INCLUDE_LEVEL__")
      seen.macroDependencies.insert(name.str());
  }
};

class AssemblyAudit : public RecursiveASTVisitor<AssemblyAudit> {
  Observations &seen;
public:
  explicit AssemblyAudit(Observations &seen) : seen(seen) {}
  bool VisitGCCAsmStmt(GCCAsmStmt *) { seen.assembly = true; return true; }
  bool VisitMSAsmStmt(MSAsmStmt *) { seen.assembly = true; return true; }
  bool VisitFileScopeAsmDecl(FileScopeAsmDecl *) { seen.assembly = true; return true; }
};

class AuditConsumer : public ASTConsumer {
  CompilerInstance &compiler;
  Observations seen;
public:
  explicit AuditConsumer(CompilerInstance &compiler) : compiler(compiler) {
    compiler.getPreprocessor().addPPCallbacks(llvm::make_unique<MacroAudit>(seen));
  }
  void HandleTranslationUnit(ASTContext &context) override {
    AssemblyAudit visitor(seen);
    visitor.TraverseDecl(context.getTranslationUnitDecl());
    auto &out = llvm::outs();
    out << "{\"profile\":1,\"macro_dependencies\":[";
    bool first = true;
    for (const auto &name : seen.macroDependencies) {
      if (!first) out << ',';
      first = false;
      out << '"' << name << '"';
    }
    out << "],\"inline_assembly\":" << (seen.assembly ? "true" : "false")
        << ",\"syntax_errors\":" << (compiler.getDiagnostics().hasErrorOccurred() ? "true" : "false")
        << ",\"complete_closure_certified\":false}\n";
  }
};

class AuditAction : public PluginASTAction {
  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &compiler,
                                                llvm::StringRef) override {
    return llvm::make_unique<AuditConsumer>(compiler);
  }
  bool ParseArgs(const CompilerInstance &, const std::vector<std::string> &args) override {
    return args.empty();
  }
};

FrontendPluginRegistry::Add<AuditAction> registered("rgec-closure", "observe native admission dependencies");
} // namespace
