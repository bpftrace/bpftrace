#include "callback_visitor.h"
#include "ast.h"

namespace bpftrace {
namespace ast {

void CallbackVisitor::visit(Integer &integer)
{
  func_(&integer);
}

void CallbackVisitor::visit(PositionalParameter &param)
{
  func_(&param);
}

void CallbackVisitor::visit(String &string)
{
  func_(&string);
}

void CallbackVisitor::visit(StackMode &mode)
{
  func_(&mode);
}

void CallbackVisitor::visit(Builtin &builtin)
{
  func_(&builtin);
}

void CallbackVisitor::visit(Identifier &identifier)
{
  func_(&identifier);
}

void CallbackVisitor::visit(Call &call)
{
  func_(&call);
  if (call.vargs)
  {
    for (Expression *expr : *call.vargs)
    {
      expr->accept(*this);
    }
  }
}

void CallbackVisitor::visit(Map &map)
{
  func_(&map);
  if (map.vargs)
  {
    for (Expression *expr : *map.vargs)
    {
      expr->accept(*this);
    }
  }
}

void CallbackVisitor::visit(Variable &var)
{
  func_(&var);
}

void CallbackVisitor::visit(Binop &binop)
{
  func_(&binop);
  binop.left->accept(*this);
  binop.right->accept(*this);
}

void CallbackVisitor::visit(Unop &unop)
{
  func_(&unop);
  if (unop.is_post_op)
  {
    unop.expr->accept(*this);
  }
  else
  {
    unop.expr->accept(*this);
  }
}

void CallbackVisitor::visit(Ternary &ternary)
{
  func_(&ternary);
  ternary.cond->accept(*this);
  ternary.left->accept(*this);
  ternary.right->accept(*this);
}

void CallbackVisitor::visit(FieldAccess &acc)
{
  func_(&acc);
  acc.expr->accept(*this);
}

void CallbackVisitor::visit(ArrayAccess &arr)
{
  func_(&arr);
  arr.expr->accept(*this);
  arr.indexpr->accept(*this);
}

void CallbackVisitor::visit(Cast &cast)
{
  func_(&cast);
  cast.expr->accept(*this);
}

void CallbackVisitor::visit(Tuple &tuple)
{
  func_(&tuple);
  for (Expression *expr : *tuple.elems)
    expr->accept(*this);
}

void CallbackVisitor::visit(ExprStatement &expr)
{
  func_(&expr);
  expr.expr->accept(*this);
}

void CallbackVisitor::visit(AssignMapStatement &assignment)
{
  func_(&assignment);
  assignment.map->accept(*this);
  assignment.expr->accept(*this);
}

void CallbackVisitor::visit(AssignVarStatement &assignment)
{
  func_(&assignment);
  assignment.var->accept(*this);
  assignment.expr->accept(*this);
}

void CallbackVisitor::visit(If &if_block)
{
  func_(&if_block);
  if_block.cond->accept(*this);
  for (Statement *stmt : *if_block.stmts)
  {
    stmt->accept(*this);
  }

  if (if_block.else_stmts)
  {
    for (Statement *stmt : *if_block.else_stmts)
    {
      stmt->accept(*this);
    }
  }
}

void CallbackVisitor::visit(Unroll &unroll)
{
  func_(&unroll);
  for (Statement *stmt : *unroll.stmts)
  {
    stmt->accept(*this);
  }
}

void CallbackVisitor::visit(While &while_block)
{
  func_(&while_block);
  while_block.cond->accept(*this);

  for (Statement *stmt : *while_block.stmts)
  {
    stmt->accept(*this);
  }
}

void CallbackVisitor::visit(Jump &jump)
{
  func_(&jump);
}

void CallbackVisitor::visit(Predicate &pred)
{
  func_(&pred);
  pred.expr->accept(*this);
}

void CallbackVisitor::visit(AttachPoint &ap)
{
  func_(&ap);
}

void CallbackVisitor::visit(Probe &probe)
{
  func_(&probe);
  for (AttachPoint *ap : *probe.attach_points)
  {
    ap->accept(*this);
  }

  if (probe.pred)
  {
    probe.pred->accept(*this);
  }

  for (Statement *stmt : *probe.stmts)
  {
    stmt->accept(*this);
  }
}

void CallbackVisitor::visit(Program &program)
{
  func_(&program);
  for (Probe *probe : *program.probes)
    probe->accept(*this);
}

} // namespace ast
} // namespace bpftrace
