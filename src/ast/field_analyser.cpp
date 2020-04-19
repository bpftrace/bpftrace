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

void FieldAnalyser::visit(Identifier &identifier)
{
  bpftrace_.btf_set_.insert(identifier.ident);
}

void FieldAnalyser::visit(Jump &jump __attribute__((unused)))
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
  else if (builtin.ident == "args")
  {
    builtin_args_ = true;
  }
  else if (builtin.ident == "retval")
  {
    auto it = ap_args_.find("$retval");

    if (it != ap_args_.end() && it->second.type == Type::cast)
      type_ = it->second.cast_type;
    else
      type_ = "";
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

void FieldAnalyser::visit(While &while_block)
{
  while_block.cond->accept(*this);

  for (Statement *stmt : *while_block.stmts)
  {
    stmt->accept(*this);
  }
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
  // visit statements in unroll once
  for (Statement *stmt : *unroll.stmts)
  {
    stmt->accept(*this);
  }
}

void FieldAnalyser::visit(FieldAccess &acc)
{
  builtin_args_ = false;

  acc.expr->accept(*this);

  if (builtin_args_)
  {
    auto it = ap_args_.find(acc.field);

    if (it != ap_args_.end() && it->second.type == Type::cast)
      type_ = it->second.cast_type;
    else
      type_ = "";

    builtin_args_ = false;
  }
  else if (!type_.empty())
  {
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
  if (ap.provider == "kfunc" || ap.provider == "kretfunc")
  {
    // starting new attach point, clear and load new
    // variables/arguments for kfunc if detected

    ap_args_.clear();

    if (!bpftrace_.btf_.resolve_args(ap.func,
                                     ap_args_,
                                     ap.provider == "kretfunc"))
    {
      // store/save args for each kfunc ap for later processing
      bpftrace_.btf_ap_args_.insert({ ap.provider + ap.func, ap_args_ });

      // pick up cast arguments immediately and let the
      // FieldAnalyser to resolve args builtin
      for (const auto& arg : ap_args_)
      {
        auto stype = arg.second;

        if (stype.type == Type::cast)
          bpftrace_.btf_set_.insert(stype.cast_type);
      }
    }
  }
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
