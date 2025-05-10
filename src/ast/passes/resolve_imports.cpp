#include "ast/passes/resolve_imports.h"
#include "ast/visitor.h"
#include "bpftrace.h"

namespace bpftrace::ast {

class ResolveImports : public Visitor<ResolveImports> {
public:
  ResolveImports(BPFtrace &bpftrace,
                 [[maybe_unused]] const std::vector<std::string> &paths)
      : bpftrace_(bpftrace) {};

  using Visitor<ResolveImports>::visit;
  void visit(Import &imp);

  // Should be called after the visit, this will move the result.
  Imports imports()
  {
    return std::move(imports_);
  }

private:
  BPFtrace &bpftrace_;
  Imports imports_;
};

void ResolveImports::visit(Import &imp)
{
  imp.addWarning() << "Imports are not yet implemented.";
}

Pass CreateResolveImportsPass(std::vector<std::string> &&import_paths)
{
  return Pass::create("ResolveImports",
                      [import_paths](ASTContext &ast, BPFtrace &b) {
                        ResolveImports analyser(b, import_paths);
                        analyser.visit(ast.root);
                      });
}

} // namespace bpftrace::ast
