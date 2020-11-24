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
      Visit(*expr);
    }
  }
}

void Visitor::visit(Map &map)
{
  if (map.vargs)
  {
    for (Expression *expr : *map.vargs)
    {
      Visit(*expr);
    }
  }
}

void Visitor::visit(Variable &var __attribute__((__unused__)))
{
}

void Visitor::visit(Binop &binop)
{
  Visit(*binop.left);
  Visit(*binop.right);
}

void Visitor::visit(Unop &unop)
{
  Visit(*unop.expr);
}

void Visitor::visit(Ternary &ternary)
{
  Visit(*ternary.cond);
  Visit(*ternary.left);
  Visit(*ternary.right);
}

void Visitor::visit(FieldAccess &acc)
{
  Visit(*acc.expr);
}

void Visitor::visit(ArrayAccess &arr)
{
  Visit(*arr.expr);
  Visit(*arr.indexpr);
}

void Visitor::visit(Cast &cast)
{
  Visit(*cast.expr);
}

void Visitor::visit(Tuple &tuple)
{
  for (Expression *expr : *tuple.elems)
    Visit(*expr);
}

void Visitor::visit(ExprStatement &expr)
{
  Visit(*expr.expr);
}

void Visitor::visit(AssignMapStatement &assignment)
{
  Visit(*assignment.map);
  Visit(*assignment.expr);
}

void Visitor::visit(AssignVarStatement &assignment)
{
  Visit(*assignment.var);
  Visit(*assignment.expr);
}

void Visitor::visit(If &if_block)
{
  Visit(*if_block.cond);

  for (Statement *stmt : *if_block.stmts)
  {
    Visit(*stmt);
  }

  if (if_block.else_stmts)
  {
    for (Statement *stmt : *if_block.else_stmts)
    {
      Visit(*stmt);
    }
  }
}

void Visitor::visit(Unroll &unroll)
{
  Visit(*unroll.expr);
  for (Statement *stmt : *unroll.stmts)
  {
    Visit(*stmt);
  }
}

void Visitor::visit(While &while_block)
{
  Visit(*while_block.cond);

  for (Statement *stmt : *while_block.stmts)
  {
    Visit(*stmt);
  }
}

void Visitor::visit(Jump &jump __attribute__((__unused__)))
{
}

void Visitor::visit(Predicate &pred)
{
  Visit(*pred.expr);
}

void Visitor::visit(AttachPoint &ap __attribute__((__unused__)))
{
}

void Visitor::visit(Probe &probe)
{
  for (AttachPoint *ap : *probe.attach_points)
  {
    Visit(*ap);
  }

  if (probe.pred)
  {
    Visit(*probe.pred);
  }
  for (Statement *stmt : *probe.stmts)
  {
    Visit(*stmt);
  }
}

void Visitor::visit(Program &program)
{
  for (Probe *probe : *program.probes)
    Visit(*probe);
}

} // namespace ast
} // namespace bpftrace
