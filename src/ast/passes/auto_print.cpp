#include "auto_print.h"

#include "log.h"

namespace bpftrace::ast {

AutoPrintAnalyser::AutoPrintAnalyser(ASTContext &ctx) : ctx_(ctx)
{
}

template <typename T>
void promote(ASTContext &ctx, ExprStatement &statement)
{
  if (auto n = dynamic_cast<T *>(statement.expr)) {
    statement.expr = ctx.make_node<ast::Call>("print",
                                              ExpressionList{ n },
                                              n->loc);
  }
}

void AutoPrintAnalyser::visit(ExprStatement &statement)
{
  // If this statement is a bare identifier, without any side-effects, then
  // automatically promote into a print statement. Note that this was
  // previously guarranteed to be optimized away during compilation, so it is
  // unlikely that any programs existed with a vestigal identifier statement.
  promote<Builtin>(ctx_, statement);
  promote<Variable>(ctx_, statement);
  promote<Map>(ctx_, statement);
  Visitor::visit(statement);
}

Pass CreateAutoPrintPass()
{
  auto fn = [](Node &n, PassContext &ctx) {
    AutoPrintAnalyser analyser(ctx.ast_ctx);
    analyser.Visit(n);
    return PassResult::Success();
  };

  return Pass("AutoPrintAnalyser", fn);
}

} // namespace bpftrace::ast
