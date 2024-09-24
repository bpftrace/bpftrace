#include "ast/visitors.h"

#include "ast/ast.h"

namespace bpftrace::ast {

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
  for (Expression *expr : call.vargs) {
    Visit(*expr);
  }
}

void Visitor::visit(Sizeof &szof)
{
  if (szof.expr)
    Visit(*szof.expr);
}

void Visitor::visit(Offsetof &ofof)
{
  if (ofof.expr)
    Visit(*ofof.expr);
}

void Visitor::visit(Map &map)
{
  if (map.key_expr)
    Visit(*map.key_expr);
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
  for (Expression *expr : tuple.elems)
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

void Visitor::visit(AssignConfigVarStatement &assignment)
{
  Visit(*assignment.expr);
}

void Visitor::visit(If &if_block)
{
  Visit(*if_block.cond);

  for (Statement *stmt : if_block.stmts) {
    Visit(*stmt);
  }

  for (Statement *stmt : if_block.else_stmts) {
    Visit(*stmt);
  }
}

void Visitor::visit(Unroll &unroll)
{
  Visit(*unroll.expr);
  for (Statement *stmt : unroll.stmts) {
    Visit(*stmt);
  }
}

void Visitor::visit(While &while_block)
{
  Visit(*while_block.cond);

  for (Statement *stmt : while_block.stmts) {
    Visit(*stmt);
  }
}

void Visitor::visit(For &for_loop)
{
  Visit(*for_loop.decl);
  Visit(*for_loop.expr);

  for (Statement *stmt : for_loop.stmts) {
    Visit(*stmt);
  }
}

void Visitor::visit(Jump &jump)
{
  if (jump.return_value)
    Visit(*jump.return_value);
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
  for (AttachPoint *ap : probe.attach_points) {
    Visit(*ap);
  }

  if (probe.pred) {
    Visit(*probe.pred);
  }
  for (Statement *stmt : probe.stmts) {
    Visit(*stmt);
  }
}

void Visitor::visit(Config &config)
{
  for (Statement *stmt : config.stmts) {
    Visit(*stmt);
  }
}

void Visitor::visit(SubprogArg &subprog_arg __attribute__((__unused__)))
{
}

void Visitor::visit(Subprog &subprog)
{
  for (SubprogArg *arg : subprog.args) {
    Visit(*arg);
  }
  for (Statement *stmt : subprog.stmts) {
    Visit(*stmt);
  }
}

void Visitor::visit(Program &program)
{
  for (Subprog *subprog : program.functions)
    Visit(*subprog);
  for (Probe *probe : program.probes)
    Visit(*probe);
  if (program.config)
    Visit(*program.config);
}

} // namespace bpftrace::ast
