#include <iostream>
#include <cassert>
#include "field_analyser.h"

namespace bpftrace {
namespace ast {

void FieldAnalyser::visit(Integer &integer __attribute__((unused)))
{
}

void FieldAnalyser::visit(PositionalParameter &param __attribute__((unused)))
{
}

void FieldAnalyser::visit(String &string __attribute__((unused)))
{
}

void FieldAnalyser::visit(StackMode &mode __attribute__((unused)))
{
}

void FieldAnalyser::visit(Identifier &identifier __attribute__((unused)))
{
}

void FieldAnalyser::visit(Builtin &builtin)
{
  if (builtin.ident == "ctx")
  {
    switch (prog_type_)
    {
      case BPF_PROG_TYPE_KPROBE:
        bpftrace_.btf_set_.insert("struct pt_regs");
        break;
      case BPF_PROG_TYPE_PERF_EVENT:
        bpftrace_.btf_set_.insert("struct bpf_perf_event_data");
        break;
      default:
        break;
    }
  }
  else if (builtin.ident == "curtask")
  {
    type_ = "struct task_struct";
    bpftrace_.btf_set_.insert(type_);
  }
}

void FieldAnalyser::visit(Call &call)
{
  if (call.vargs) {
    for (Expression *expr : *call.vargs) {
      expr->accept(*this);
    }
  }
}

void FieldAnalyser::visit(Map &map)
{
  MapKey key;
  if (map.vargs) {
    for (Expression *expr : *map.vargs) {
      expr->accept(*this);
    }
  }
}

void FieldAnalyser::visit(Variable &var __attribute__((unused)))
{
}

void FieldAnalyser::visit(ArrayAccess &arr)
{
  arr.expr->accept(*this);
  arr.indexpr->accept(*this);
}

void FieldAnalyser::visit(Binop &binop)
{
  binop.left->accept(*this);
  binop.right->accept(*this);
}

void FieldAnalyser::visit(Unop &unop)
{
  unop.expr->accept(*this);
}

void FieldAnalyser::visit(Ternary &ternary)
{
  ternary.cond->accept(*this);
  ternary.left->accept(*this);
  ternary.right->accept(*this);
}

void FieldAnalyser::visit(If &if_block)
{
  if_block.cond->accept(*this);

  for (Statement *stmt : *if_block.stmts) {
    stmt->accept(*this);
  }

  if (if_block.else_stmts) {
    for (Statement *stmt : *if_block.else_stmts) {
      stmt->accept(*this);
    }
  }
}

void FieldAnalyser::visit(Unroll &unroll)
{
  for (int i=0; i < unroll.var; i++) {
    for (Statement *stmt : *unroll.stmts) {
      stmt->accept(*this);
    }
  }
}

void FieldAnalyser::visit(FieldAccess &acc)
{
  acc.expr->accept(*this);
  if (!type_.empty()) {
    type_ = bpftrace_.btf_.type_of(type_, acc.field);
    bpftrace_.btf_set_.insert(type_);
  }
}

void FieldAnalyser::visit(Cast &cast)
{
  cast.expr->accept(*this);
  type_ = cast.cast_type;
  assert(!type_.empty());
  bpftrace_.btf_set_.insert(type_);
}

void FieldAnalyser::visit(ExprStatement &expr)
{
  expr.expr->accept(*this);
}

void FieldAnalyser::visit(AssignMapStatement &assignment)
{
  assignment.map->accept(*this);
  assignment.expr->accept(*this);
}

void FieldAnalyser::visit(AssignVarStatement &assignment)
{
  assignment.expr->accept(*this);
}

void FieldAnalyser::visit(Predicate &pred)
{
  pred.expr->accept(*this);
}

void FieldAnalyser::visit(AttachPoint &ap __attribute__((unused)))
{
}

void FieldAnalyser::visit(Probe &probe)
{
  for (AttachPoint *ap : *probe.attach_points) {
    ap->accept(*this);
    ProbeType pt = probetype(ap->provider);
    prog_type_ = progtype(pt);
  }
  if (probe.pred) {
    probe.pred->accept(*this);
  }
  for (Statement *stmt : *probe.stmts) {
    stmt->accept(*this);
  }
}

void FieldAnalyser::visit(Program &program)
{
  for (Probe *probe : *program.probes)
    probe->accept(*this);
}

int FieldAnalyser::analyse()
{
  if (bpftrace_.btf_.has_data())
    root_->accept(*this);
  return 0;
}

} // namespace ast
} // namespace bpftrace
