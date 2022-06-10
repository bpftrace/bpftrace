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
  if (builtin.ident == "ctx")
  {
    switch (prog_type_)
    {
      case libbpf::BPF_PROG_TYPE_KPROBE:
        bpftrace_.btf_set_.insert("struct pt_regs");
        break;
      case libbpf::BPF_PROG_TYPE_PERF_EVENT:
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
    resolve_args(*probe_);
    has_builtin_args_ = true;
  }
  else if (builtin.ident == "retval")
  {
    resolve_args(*probe_);

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

    bpftrace_.btf_set_.insert(type_);
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
  {
    type_ = it->second.first;
    sized_type_ = it->second.second;
  }
}

void FieldAnalyser::visit(Variable &var __attribute__((unused)))
{
  auto it = var_types_.find(var.ident);
  if (it != var_types_.end())
  {
    type_ = it->second.first;
    sized_type_ = it->second.second;
  }
}

void FieldAnalyser::visit(FieldAccess &acc)
{
  has_builtin_args_ = false;

  Visit(*acc.expr);

  if (has_builtin_args_)
  {
    auto it = ap_args_.find(acc.field);

    if (it != ap_args_.end())
    {
      if (it->second.IsRecordTy())
        type_ = it->second.GetName();
      else if (it->second.IsPtrTy() && it->second.GetPointeeTy()->IsRecordTy())
        type_ = it->second.GetPointeeTy()->GetName();
      else
        type_ = "";
      sized_type_ = it->second;
    }

    bpftrace_.btf_set_.insert(type_);
    has_builtin_args_ = false;
  }
  else if (!type_.empty())
  {
    type_ = bpftrace_.btf_.type_of(type_, acc.field);
    bpftrace_.btf_set_.insert(type_);

    if (sized_type_.IsPtrTy())
    {
      sized_type_ = *sized_type_.GetPointeeTy();
      resolve_fields(sized_type_);
    }

    if (sized_type_.IsRecordTy() && sized_type_.HasField(acc.field))
      sized_type_ = sized_type_.GetField(acc.field).type;
  }
}

void FieldAnalyser::visit(Cast &cast)
{
  Visit(*cast.expr);
  type_ = cast.cast_type;
  assert(!type_.empty());
  bpftrace_.btf_set_.insert(type_);

  for (auto &ap : *probe_->attach_points)
    if (Dwarf *dwarf = bpftrace_.get_dwarf(*ap))
      sized_type_ = dwarf->get_stype(cast.cast_type);
}

void FieldAnalyser::visit(AssignMapStatement &assignment)
{
  Visit(*assignment.map);
  Visit(*assignment.expr);
  var_types_.emplace(assignment.map->ident, std::make_pair(type_, sized_type_));
}

void FieldAnalyser::visit(AssignVarStatement &assignment)
{
  Visit(*assignment.expr);
  var_types_.emplace(assignment.var->ident, std::make_pair(type_, sized_type_));
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
    // BEGIN and END are special uprobe cases that do not have args
    if (ap->provider == "BEGIN" || ap->provider == "END")
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

        // Trying to attach to multiple kfuncs. If some of them fails on
        // argument resolution, do not fail hard, just print a warning and
        // continue with other functions.
        if (probe_type == ProbeType::kfunc || probe_type == ProbeType::kretfunc)
        {
          try
          {
            bpftrace_.btf_.resolve_args(match,
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
          std::string func = match;
          std::string file = erase_prefix(func);

          Dwarf *dwarf = bpftrace_.get_dwarf(file);
          if (dwarf)
          {
            args = dwarf->resolve_args(func);
            if (first)
              ap_args_ = args;
          }
          else
            LOG(WARNING, ap->loc, err_) << "No debuginfo found for " << file;
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
          bpftrace_.btf_.resolve_args(ap->func,
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
      dwarf->resolve_fields(sized_type_);
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
