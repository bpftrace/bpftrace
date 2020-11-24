#include "visitors.h"
#include "ast.h"

namespace bpftrace {
namespace ast {

void Visitor::visit(Integer &integer __attribute__((__unused__)))
{
}

void Visitor::visit(PositionalParameter &param __attribute__((__unused__)))
{
}

void Visitor::visit(String &string __attribute__((__unused__)))
{
}

void Visitor::visit(StackMode &mode __attribute__((__unused__)))
{
}

void Visitor::visit(Builtin &builtin __attribute__((__unused__)))
{
}

void Visitor::visit(Identifier &identifier __attribute__((__unused__)))
{
}

void Visitor::visit(Call &call)
{
  if (call.vargs)
  {
    for (Expression *expr : *call.vargs)
    {
      expr->accept(*this);
    }
  }
}

void Visitor::visit(Map &map)
{
  if (map.vargs)
  {
    for (Expression *expr : *map.vargs)
    {
      expr->accept(*this);
    }
  }
}

void Visitor::visit(Variable &var __attribute__((__unused__)))
{
}

void Visitor::visit(Binop &binop)
{
  binop.left->accept(*this);
  binop.right->accept(*this);
}

void Visitor::visit(Unop &unop)
{
  unop.expr->accept(*this);
}

void Visitor::visit(Ternary &ternary)
{
  ternary.cond->accept(*this);
  ternary.left->accept(*this);
  ternary.right->accept(*this);
}

void Visitor::visit(FieldAccess &acc)
{
  acc.expr->accept(*this);
}

void Visitor::visit(ArrayAccess &arr)
{
  arr.expr->accept(*this);
  arr.indexpr->accept(*this);
}

void Visitor::visit(Cast &cast)
{
  cast.expr->accept(*this);
}

void Visitor::visit(Tuple &tuple)
{
  for (Expression *expr : *tuple.elems)
    expr->accept(*this);
}

void Visitor::visit(ExprStatement &expr)
{
  expr.expr->accept(*this);
}

void Visitor::visit(AssignMapStatement &assignment)
{
  assignment.map->accept(*this);
  assignment.expr->accept(*this);
}

void Visitor::visit(AssignVarStatement &assignment)
{
  assignment.var->accept(*this);
  assignment.expr->accept(*this);
}

void Visitor::visit(If &if_block)
{
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

void Visitor::visit(Unroll &unroll)
{
  unroll.expr->accept(*this);
  for (Statement *stmt : *unroll.stmts)
  {
    stmt->accept(*this);
  }
}

void Visitor::visit(While &while_block)
{
  while_block.cond->accept(*this);

  for (Statement *stmt : *while_block.stmts)
  {
    stmt->accept(*this);
  }
}

void Visitor::visit(Jump &jump __attribute__((__unused__)))
{
}

void Visitor::visit(Predicate &pred)
{
  pred.expr->accept(*this);
}

void Visitor::visit(AttachPoint &ap __attribute__((__unused__)))
{
}

void Visitor::visit(Probe &probe)
{
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

void Visitor::visit(Program &program)
{
  for (Probe *probe : *program.probes)
    probe->accept(*this);
}

} // namespace ast
} // namespace bpftrace
