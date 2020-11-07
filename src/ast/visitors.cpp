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

template <typename T>
T *Mutator::Value(Node *n)
{
  return reinterpret_cast<T *>(Visit(*n));
}

ExpressionList *Mutator::mutateExprList(ExpressionList *src)
{
  auto dst = new ExpressionList;
  for (auto expr : *src)
    dst->push_back(Value<Expression>(expr));
  return dst;
}

StatementList *Mutator::mutateStmtList(StatementList *src)
{
  auto dst = new StatementList;
  for (auto expr : *src)
    dst->push_back(Value<Statement>(expr));
  return dst;
}

#define DEFINE_MUTATOR_LEAF(OP)                                                \
  Node *Mutator::visit(OP &v)                                                  \
  {                                                                            \
    return v.leafcopy();                                                       \
  }

DEFINE_MUTATOR_LEAF(Integer)
DEFINE_MUTATOR_LEAF(PositionalParameter)
DEFINE_MUTATOR_LEAF(String)
DEFINE_MUTATOR_LEAF(StackMode)
DEFINE_MUTATOR_LEAF(Builtin)
DEFINE_MUTATOR_LEAF(Identifier)
DEFINE_MUTATOR_LEAF(Variable)
DEFINE_MUTATOR_LEAF(Jump)
DEFINE_MUTATOR_LEAF(AttachPoint)

#undef DEFINE_MUTATOR_LEAF

Node *Mutator::visit(Call &call)
{
  auto c = call.leafcopy();
  if (call.vargs)
    c->vargs = mutateExprList(call.vargs);
  return c;
}

Node *Mutator::visit(Map &map)
{
  auto m = map.leafcopy();
  if (map.vargs)
  {
    m->vargs = mutateExprList(map.vargs);

    for (auto expr : *m->vargs)
      expr->key_for_map = m;
  }
  return m;
}

Node *Mutator::visit(Binop &binop)
{
  auto b = binop.leafcopy();
  b->left = Value<Expression>(binop.left);
  b->right = Value<Expression>(binop.right);

  return b;
}

Node *Mutator::visit(Unop &unop)
{
  auto u = unop.leafcopy();
  u->expr = Value<Expression>(unop.expr);
  return u;
}

Node *Mutator::visit(Ternary &ternary)
{
  auto cond = Value<Expression>(ternary.cond);
  auto left = Value<Expression>(ternary.left);
  auto right = Value<Expression>(ternary.right);
  return new Ternary(cond, left, right, ternary.loc);
}

Node *Mutator::visit(FieldAccess &acc)
{
  auto f = acc.leafcopy();
  f->expr = Value<Expression>(acc.expr);
  return f;
}

Node *Mutator::visit(ArrayAccess &arr)
{
  auto a = arr.leafcopy();
  a->expr = Value<Expression>(arr.expr);
  a->indexpr = Value<Expression>(arr.indexpr);
  return a;
}

Node *Mutator::visit(Cast &cast)
{
  auto c = cast.leafcopy();
  c->expr = Value<Expression>(cast.expr);
  return c;
}

Node *Mutator::visit(Tuple &tuple)
{
  auto t = tuple.leafcopy();
  t->elems = mutateExprList(tuple.elems);
  return t;
}

Node *Mutator::visit(ExprStatement &expr)
{
  auto e = expr.leafcopy();
  e->expr = Value<Expression>(expr.expr);
  return e;
}

Node *Mutator::visit(AssignMapStatement &assignment)
{
  auto a = assignment.leafcopy();
  a->map = Value<Map>(assignment.map);
  a->expr = Value<Expression>(assignment.expr);
  a->expr->map = a->map;
  return a;
}

Node *Mutator::visit(AssignVarStatement &assignment)
{
  auto a = assignment.leafcopy();
  a->var = Value<Variable>(assignment.var);
  a->expr = Value<Expression>(assignment.expr);
  return a;
}

Node *Mutator::visit(If &if_block)
{
  auto i = if_block.leafcopy();

  i->cond = Value<Expression>(if_block.cond);

  i->stmts = mutateStmtList(if_block.stmts);

  if (if_block.else_stmts)
    i->else_stmts = mutateStmtList(if_block.else_stmts);

  return i;
}

Node *Mutator::visit(Unroll &unroll)
{
  auto u = unroll.leafcopy();
  u->expr = Value<Expression>(unroll.expr);
  u->stmts = mutateStmtList(unroll.stmts);
  return u;
}

Node *Mutator::visit(While &while_block)
{
  auto w = while_block.leafcopy();
  w->cond = Value<Expression>(while_block.cond);

  w->stmts = mutateStmtList(while_block.stmts);
  return w;
}

Node *Mutator::visit(Probe &probe)
{
  auto p = probe.leafcopy();
  p->attach_points = new AttachPointList;
  for (AttachPoint *ap : *probe.attach_points)
    p->attach_points->push_back(Value<AttachPoint>(ap));

  if (probe.pred)
    p->pred = Value<Predicate>(probe.pred);

  p->stmts = mutateStmtList(probe.stmts);
  return p;
}

Node *Mutator::visit(Program &program)
{
  auto p = program.leafcopy();
  p->probes = new ProbeList;
  for (Probe *probe : *program.probes)
    p->probes->push_back(Value<Probe>(probe));
  return p;
}

Node *Mutator::visit(Predicate &pred)
{
  auto p = pred.leafcopy();
  p->expr = Value<Expression>(pred.expr);
  return p;
}

} // namespace ast
} // namespace bpftrace
