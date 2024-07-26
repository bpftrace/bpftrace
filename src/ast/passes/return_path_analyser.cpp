#include "return_path_analyser.h"
#include "log.h"

namespace bpftrace {
namespace ast {

ReturnPathAnalyser::ReturnPathAnalyser(Node *root, std::ostream &out)
    : root_(root), out_(out)
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
    if (Visit(*stmt))
      return true;
  }
  LOG(ERROR, subprog.loc, err_) << "Not all code paths returned a value";
  return false;
}

bool ReturnPathAnalyser::visit(Jump &jump)
{
  return jump.ident == JumpType::RETURN;
}

bool ReturnPathAnalyser::visit(If &if_stmt)
{
  bool result = false;
  for (Statement *stmt : if_stmt.stmts) {
    if (Visit(*stmt))
      result = true;
  }
  if (!result) {
    // if block has no return
    return false;
  }

  for (Statement *stmt : if_stmt.else_stmts) {
    if (Visit(*stmt)) {
      // both blocks have a return
      return true;
    }
  }
  // else block has no return (or there is no else block)
  return false;
}

bool ReturnPathAnalyser::default_visitor(__attribute__((unused)) Node &node)
{
  // not a return instruction
  return false;
}

int ReturnPathAnalyser::analyse()
{
  int result = Visit(*root_) ? 0 : 1;
  if (result)
    out_ << err_.str();
  return result;
}

Pass CreateReturnPathPass()
{
  auto fn = [](Node &n, __attribute__((unused)) PassContext &ctx) {
    auto return_path = ReturnPathAnalyser(&n);
    int err = return_path.analyse();
    if (err)
      return PassResult::Error("ReturnPath");
    return PassResult::Success();
  };

  return Pass("ReturnPath", fn);
}

} // namespace ast
} // namespace bpftrace
