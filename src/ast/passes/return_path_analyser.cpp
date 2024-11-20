#include "return_path_analyser.h"
#include "log.h"

namespace bpftrace::ast {

ReturnPathAnalyser::ReturnPathAnalyser(ASTContext &ctx, std::ostream &out)
    : Visitor<ReturnPathAnalyser, bool>(ctx), out_(out)
{
}

bool ReturnPathAnalyser::visit(Program &prog)
{
  for (Subprog *subprog : prog.functions) {
    if (!visit(*subprog))
      return false;
  }
  return true;
}

bool ReturnPathAnalyser::visit(Subprog &subprog)
{
  if (subprog.return_type.IsVoidTy())
    return true;

  for (Statement *stmt : subprog.stmts) {
    if (visit(*stmt))
      return true;
  }
  LOG(ERROR, subprog.loc, err_) << "Not all code paths returned a value";
  return false;
}

bool ReturnPathAnalyser::visit(Jump &jump)
{
  return jump.ident == JumpType::RETURN;
}

bool ReturnPathAnalyser::visit(If &if_node)
{
  bool result = false;
  for (Statement *stmt : if_node.if_block->stmts) {
    if (visit(stmt))
      result = true;
  }
  if (!result) {
    // if block has no return
    return false;
  }

  for (Statement *stmt : if_node.else_block->stmts) {
    if (visit(stmt)) {
      // both blocks have a return
      return true;
    }
  }
  // else block has no return (or there is no else block)
  return false;
}

int ReturnPathAnalyser::analyse()
{
  int result = visit(ctx_.root) ? 0 : 1;
  if (result)
    out_ << err_.str();
  return result;
}

Pass CreateReturnPathPass()
{
  auto fn = [](PassContext &ctx) {
    auto return_path = ReturnPathAnalyser(ctx.ast_ctx);
    int err = return_path.analyse();
    if (err)
      return PassResult::Error("ReturnPath");
    return PassResult::Success();
  };

  return Pass("ReturnPath", fn);
}

} // namespace bpftrace::ast
