#include "field_analyser.h"
#include "log.h"
#include <cassert>
#include <iostream>

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

void FieldAnalyser::check_kfunc_args(void)
{
  if (has_kfunc_probe_ && has_mixed_args_)
  {
    LOG(ERROR, mixed_args_loc_, err_)
        << "Probe has attach points with mixed arguments";
  }
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
    has_builtin_args_ = true;
  }
  else if (builtin.ident == "retval")
  {
    check_kfunc_args();

    auto it = ap_args_.find("$retval");

    if (it != ap_args_.end())
    {
      if (it->second.IsRecordTy())
        type_ = it->second.GetName();
      else if (it->second.IsPtrTy() && it->second.GetPointeeTy()->IsRecordTy())
        type_ = it->second.GetPointeeTy()->GetName();
      else
        type_ = "";
    }
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

  auto it = var_types_.find(map.ident);
  if (it != var_types_.end())
    type_ = it->second;
}

void FieldAnalyser::visit(Variable &var __attribute__((unused)))
{
  auto it = var_types_.find(var.ident);
  if (it != var_types_.end())
    type_ = it->second;
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
  has_builtin_args_ = false;

  acc.expr->accept(*this);

  if (has_builtin_args_)
  {
    check_kfunc_args();

    auto it = ap_args_.find(acc.field);

    if (it != ap_args_.end())
    {
      if (it->second.IsRecordTy())
        type_ = it->second.GetName();
      else if (it->second.IsPtrTy() && it->second.GetPointeeTy()->IsRecordTy())
        type_ = it->second.GetPointeeTy()->GetName();
      else
        type_ = "";
    }

    bpftrace_.btf_set_.insert(type_);
    has_builtin_args_ = false;
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

void FieldAnalyser::visit(Tuple &tuple)
{
  for (Expression *expr : *tuple.elems)
    expr->accept(*this);
}

void FieldAnalyser::visit(ExprStatement &expr)
{
  expr.expr->accept(*this);
}

void FieldAnalyser::visit(AssignMapStatement &assignment)
{
  assignment.map->accept(*this);
  assignment.expr->accept(*this);
  var_types_.emplace(assignment.map->ident, type_);
}

void FieldAnalyser::visit(AssignVarStatement &assignment)
{
  assignment.expr->accept(*this);
  var_types_.emplace(assignment.var->ident, type_);
}

void FieldAnalyser::visit(Predicate &pred)
{
  pred.expr->accept(*this);
}

bool FieldAnalyser::compare_args(const std::map<std::string, SizedType>& args1,
                                 const std::map<std::string, SizedType>& args2)
{
  auto pred = [](auto a, auto b) { return a.first == b.first; };

  return args1.size() == args2.size() &&
         std::equal(args1.begin(), args1.end(), args2.begin(), pred);
}

bool FieldAnalyser::resolve_args(AttachPoint &ap)
{
  bool kretfunc = ap.provider == "kretfunc";
  std::string func = ap.func;

  // load AP arguments into ap_args_
  ap_args_.clear();

  if (ap.need_expansion)
  {
    std::set<std::string> matches;

    // Find all the matches for the wildcard..
    try
    {
      matches = bpftrace_.find_wildcard_matches(ap);
    }
    catch (const WildcardException &e)
    {
      std::cerr << e.what() << std::endl;
      return false;
    }

    // ... and check if they share same arguments.
    //
    // If they have different arguments, we have a potential
    // problem, but only if the 'args->arg' is actually used.
    // So far we just set has_mixed_args_ bool and continue.

    bool first = true;

    for (auto func : matches)
    {
      std::map<std::string, SizedType> args;

      // Trying to attach to multiple kfuncs. If some of them fails on argument
      // resolution, do not fail hard, just print a warning and continue with
      // other functions.
      try
      {
        bpftrace_.btf_.resolve_args(func, first ? ap_args_ : args, kretfunc);
      }
      catch (const std::runtime_error &e)
      {
        LOG(WARNING) << "kfunc:" << ap.func << ": " << e.what();
        continue;
      }

      if (!first && !compare_args(args, ap_args_))
      {
        has_mixed_args_ = true;
        mixed_args_loc_ = ap.loc;
        break;
      }

      first = false;
    }
  }
  else
  {
    // Resolving args for an explicit function failed, print an error and fail
    try
    {
      bpftrace_.btf_.resolve_args(ap.func, ap_args_, kretfunc);
    }
    catch (const std::runtime_error &e)
    {
      LOG(ERROR, ap.loc, err_) << "kfunc:" << ap.func << ": " << e.what();
      return false;
    }
  }

  // check if we already stored arguments for this probe
  auto it = bpftrace_.btf_ap_args_.find(probe_->name());

  if (it != bpftrace_.btf_ap_args_.end())
  {
    // we did, and it's different.. save the state and
    // triger the error if there's args->xxx detected
    if (!compare_args(it->second, ap_args_))
    {
      has_mixed_args_ = true;
      mixed_args_loc_ = ap.loc;
    }
  }
  else
  {
    // store/save args for each kfunc ap for later processing
    bpftrace_.btf_ap_args_.insert({ probe_->name(), ap_args_ });
  }
  return true;
}

void FieldAnalyser::visit(AttachPoint &ap)
{
  if (ap.provider == "kfunc" || ap.provider == "kretfunc")
  {
    has_kfunc_probe_ = true;

    // starting new attach point, clear and load new
    // variables/arguments for kfunc if detected
    if (resolve_args(ap))
    {
      // pick up cast arguments immediately and let the
      // FieldAnalyser to resolve args builtin
      for (const auto& arg : ap_args_)
      {
        auto stype = arg.second;

        if (stype.IsRecordTy())
          bpftrace_.btf_set_.insert(stype.GetName());
      }
    }
  }
}

void FieldAnalyser::visit(Probe &probe)
{
  has_kfunc_probe_ = false;
  has_mixed_args_ = false;
  probe_ = &probe;

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

  std::string errors = err_.str();
  if (!errors.empty())
  {
    out_ << errors;
    return 1;
  }

  return 0;
}

} // namespace ast
} // namespace bpftrace
