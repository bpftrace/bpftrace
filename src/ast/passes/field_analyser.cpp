#include "field_analyser.h"

#include <cassert>
#include <iostream>

#include "dwarf_parser.h"
#include "log.h"
#include "probe_matcher.h"

namespace bpftrace {
namespace ast {

void FieldAnalyser::visit(Identifier &identifier)
{
  bpftrace_.btf_set_.insert(identifier.ident);
}

void FieldAnalyser::visit(Builtin &builtin)
{
  std::string builtin_type;
  sized_type_ = CreateNone();
  if (builtin.ident == "ctx")
  {
    switch (prog_type_)
    {
      case libbpf::BPF_PROG_TYPE_KPROBE:
        builtin_type = "struct pt_regs";
        break;
      case libbpf::BPF_PROG_TYPE_PERF_EVENT:
        builtin_type = "struct bpf_perf_event_data";
        break;
      default:
        break;
    }
    // For each iterator probe, the context is pointing to specific struct,
    // make them resolved and available
    if (probe_type_ == ProbeType::iter)
    {
      if (attach_func_ == "task")
        builtin_type = "struct bpf_iter__task";
      else if (attach_func_ == "task_file")
        builtin_type = "struct bpf_iter__task_file";
      else if (attach_func_ == "task_vma")
        builtin_type = "struct bpf_iter__task_vma";
    }
  }
  else if (builtin.ident == "curtask")
  {
    builtin_type = "struct task_struct";
  }
  else if (builtin.ident == "args")
  {
    resolve_args(*probe_);
    has_builtin_args_ = true;
    return;
  }
  else if (builtin.ident == "retval")
  {
    resolve_args(*probe_);

    auto it = ap_args_.find("$retval");
    if (it != ap_args_.end())
      sized_type_ = it->second;
    return;
  }

  if (bpftrace_.has_btf_data())
    sized_type_ = bpftrace_.btf_->get_stype(builtin_type);
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
    sized_type_ = it->second;
}

void FieldAnalyser::visit(Variable &var __attribute__((unused)))
{
  auto it = var_types_.find(var.ident);
  if (it != var_types_.end())
    sized_type_ = it->second;
}

void FieldAnalyser::visit(FieldAccess &acc)
{
  has_builtin_args_ = false;

  Visit(*acc.expr);

  if (has_builtin_args_)
  {
    auto it = ap_args_.find(acc.field);
    if (it != ap_args_.end())
      sized_type_ = it->second;

    has_builtin_args_ = false;
  }
  else if (!sized_type_.IsNoneTy())
  {
    if (sized_type_.IsPtrTy())
    {
      sized_type_ = *sized_type_.GetPointeeTy();
      resolve_fields(sized_type_);
    }

    // If the struct type or the field type has not been resolved, add the type
    // to the BTF set to let ClangParser resolve it
    if (bpftrace_.has_btf_data() && sized_type_.IsRecordTy())
    {
      SizedType field_type = CreateNone();
      if (sized_type_.HasField(acc.field))
        field_type = sized_type_.GetField(acc.field).type;

      if (!field_type.IsNoneTy())
        sized_type_ = field_type;
      else
      {
        bpftrace_.btf_set_.insert(sized_type_.GetName());
        auto field_type_name = bpftrace_.btf_->type_of(sized_type_.GetName(),
                                                       acc.field);
        bpftrace_.btf_set_.insert(field_type_name);
      }
    }
  }
}

void FieldAnalyser::visit(Cast &cast)
{
  Visit(*cast.expr);
  sized_type_ = CreateNone();

  for (auto &ap : *probe_->attach_points)
    if (Dwarf *dwarf = bpftrace_.get_dwarf(*ap))
      sized_type_ = dwarf->get_stype(cast.cast_type);

  if (sized_type_.IsNoneTy() && bpftrace_.has_btf_data())
    sized_type_ = bpftrace_.btf_->get_stype(cast.cast_type);

  // Could not resolve destination type - let ClangParser do it
  if (sized_type_.IsNoneTy())
    bpftrace_.btf_set_.insert(cast.cast_type);
}

void FieldAnalyser::visit(AssignMapStatement &assignment)
{
  Visit(*assignment.map);
  Visit(*assignment.expr);
  var_types_.emplace(assignment.map->ident, sized_type_);
}

void FieldAnalyser::visit(AssignVarStatement &assignment)
{
  Visit(*assignment.expr);
  var_types_.emplace(assignment.var->ident, sized_type_);
}

bool FieldAnalyser::compare_args(const ProbeArgs &args1, const ProbeArgs &args2)
{
  using ProbeArgsValue = ProbeArgs::value_type;
  auto pred = [](const ProbeArgsValue &a, const ProbeArgsValue &b) {
    return a.first == b.first;
  };

  return args1.size() == args2.size() &&
         std::equal(args1.begin(), args1.end(), args2.begin(), pred);
}

bool FieldAnalyser::resolve_args(Probe &probe)
{
  // load AP arguments into ap_args_
  ap_args_.clear();

  for (auto *ap : *probe.attach_points)
  {
    auto probe_type = probetype(ap->provider);
    if (probe_type != ProbeType::kfunc && probe_type != ProbeType::kretfunc &&
        probe_type != ProbeType::uprobe)
      continue;

    if (ap->need_expansion)
    {
      std::set<std::string> matches;

      // Find all the matches for the wildcard..
      try
      {
        matches = bpftrace_.probe_matcher_->get_matches_for_ap(*ap);
      }
      catch (const WildcardException &e)
      {
        LOG(ERROR) << e.what();
        return false;
      }

      // ... and check if they share same arguments.

      bool first = true;

      for (auto &match : matches)
      {
        ProbeArgs args;
        // Both uprobes and kfuncs have a target (binary for uprobes, kernel
        // module for kfuncs).
        std::string func = match;
        std::string target = erase_prefix(func);

        // Trying to attach to multiple kfuncs. If some of them fails on
        // argument resolution, do not fail hard, just print a warning and
        // continue with other functions.
        if (probe_type == ProbeType::kfunc || probe_type == ProbeType::kretfunc)
        {
          try
          {
            bpftrace_.btf_->resolve_args(func,
                                         first ? ap_args_ : args,
                                         probe_type == ProbeType::kretfunc);
          }
          catch (const std::runtime_error &e)
          {
            LOG(WARNING) << "kfunc:" << ap->func << ": " << e.what();
            continue;
          }
        }
        else // uprobe
        {
          Dwarf *dwarf = bpftrace_.get_dwarf(target);
          if (dwarf)
          {
            args = dwarf->resolve_args(func);
            if (first)
              ap_args_ = args;
          }
          else
            LOG(WARNING, ap->loc, err_) << "No debuginfo found for " << target;
        }

        if (!first && !compare_args(args, ap_args_))
        {
          LOG(ERROR, ap->loc, err_)
              << "Probe has attach points with mixed arguments";
          break;
        }

        first = false;
      }
    }
    else
    {
      // Resolving args for an explicit function failed, print an error and fail
      if (probe_type == ProbeType::kfunc || probe_type == ProbeType::kretfunc)
      {
        try
        {
          bpftrace_.btf_->resolve_args(ap->func,
                                       ap_args_,
                                       probe_type == ProbeType::kretfunc);
        }
        catch (const std::runtime_error &e)
        {
          LOG(ERROR, ap->loc, err_) << "kfunc:" << ap->func << ": " << e.what();
          return false;
        }
      }
      else // uprobe
      {
        Dwarf *dwarf = bpftrace_.get_dwarf(ap->target);
        if (dwarf)
          ap_args_ = dwarf->resolve_args(ap->func);
        else
        {
          LOG(ERROR, ap->loc, err_) << "No debuginfo found for " << ap->target;
        }
      }
    }

    // check if we already stored arguments for this probe
    auto it = bpftrace_.ap_args_.find(probe_->name());

    if (it != bpftrace_.ap_args_.end())
    {
      // we did, and it's different...trigger the error
      if (!compare_args(it->second, ap_args_))
      {
        LOG(ERROR, ap->loc, err_)
            << "Probe has attach points with mixed arguments";
      }
    }
    else
    {
      // store/save args for each ap for later processing
      bpftrace_.ap_args_.insert({ probe_->name(), ap_args_ });
    }
  }
  return true;
}

void FieldAnalyser::resolve_fields(SizedType &type)
{
  if (!type.IsRecordTy())
    return;

  for (auto &ap : *probe_->attach_points)
    if (Dwarf *dwarf = bpftrace_.get_dwarf(*ap))
      dwarf->resolve_fields(type);

  if (type.GetFieldCount() == 0 && bpftrace_.has_btf_data())
    bpftrace_.btf_->resolve_fields(type);
}

void FieldAnalyser::visit(Probe &probe)
{
  probe_ = &probe;

  for (AttachPoint *ap : *probe.attach_points) {
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
