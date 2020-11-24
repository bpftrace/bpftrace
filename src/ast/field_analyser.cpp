#include "field_analyser.h"
#include "log.h"
#include "probe_matcher.h"
#include <cassert>
#include <iostream>

namespace bpftrace {
namespace ast {

void FieldAnalyser::visit(Identifier &identifier)
{
  bpftrace_.btf_set_.insert(identifier.ident);
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
    // For each iterator probe, the context is pointing to specific struct,
    // make them resolved and available
    if (probe_type_ == ProbeType::iter)
    {
      std::string it_struct;

      if (attach_func_ == "task")
      {
        it_struct = "struct bpf_iter__task";
      }
      else if (attach_func_ == "task_file")
      {
        it_struct = "struct bpf_iter__task_file";
      }

      if (!it_struct.empty())
      {
        bpftrace_.btf_set_.insert(it_struct);
        type_ = it_struct;
      }
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

void FieldAnalyser::visit(Map &map)
{
  MapKey key;
  if (map.vargs) {
    for (Expression *expr : *map.vargs) {
      Visit(*expr);
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

void FieldAnalyser::visit(FieldAccess &acc)
{
  has_builtin_args_ = false;

  Visit(*acc.expr);

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
  Visit(*cast.expr);
  type_ = cast.cast_type;
  assert(!type_.empty());
  bpftrace_.btf_set_.insert(type_);
}

void FieldAnalyser::visit(AssignMapStatement &assignment)
{
  Visit(*assignment.map);
  Visit(*assignment.expr);
  var_types_.emplace(assignment.map->ident, type_);
}

void FieldAnalyser::visit(AssignVarStatement &assignment)
{
  Visit(*assignment.expr);
  var_types_.emplace(assignment.var->ident, type_);
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
      matches = bpftrace_.probe_matcher_->get_matches_for_ap(ap);
    }
    catch (const WildcardException &e)
    {
      LOG(ERROR) << e.what();
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

        if (stype.IsPtrTy())
          stype = *stype.GetPointeeTy();

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
    Visit(*ap);
    probe_type_ = probetype(ap->provider);
    prog_type_ = progtype(probe_type_);
    attach_func_ = ap->func;
  }
  if (probe.pred) {
    Visit(*probe.pred);
  }
  for (Statement *stmt : *probe.stmts) {
    Visit(*stmt);
  }
}

int FieldAnalyser::analyse()
{
  if (!bpftrace_.btf_.has_data())
    return 0;

  Visit(*root_);

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
