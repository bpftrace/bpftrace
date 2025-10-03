#include "ast_matchers.h"
#include "ast/passes/printer.h"

namespace bpftrace::ast {

void PrintTo(const ASTContext& ast, std::ostream* os)
{
  Printer printer(*os);
  printer.visit(*ast.root);
}

} // namespace bpftrace::ast
