#include <iostream>
#include <sstream>
#include <unordered_set>

#include "ast/passes/resolve_imports.h"
#include "ast/visitor.h"
#include "bpftrace.h"
#include "log.h"

namespace bpftrace::ast {

class ResolveImports : public Visitor<ResolveImports> {
public:
  ResolveImports(BPFtrace &bpftrace, const std::vector<std::string> &paths)
      : bpftrace_(bpftrace), paths_(paths) {};

  using Visitor<ResolveImports>::visit;
  void visit(Import &imp);

  // Should be called after the visit, this will move the result.
  Imports imports()
  {
    return std::move(imports_);
  }

private:
  BPFtrace &bpftrace_;
  const std::vector<std::string> &paths_;
  Imports imports_;
};

void ResolveImports::visit(Import &imp)
{
  if (!bpftrace_.config_->get(ConfigKeyBool::unstable_import)) {
    imp.addError() << "Imports are not enabled by default. To enable "
                      "this unstable feature, set this config flag to 1 "
                      "e.g. unstable_import=1";
    return;
  }

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
