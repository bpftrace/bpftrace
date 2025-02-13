#include "field_analyser.h"

#include <cassert>
#include <iostream>

#include "arch/arch.h"
#include "dwarf_parser.h"
#include "log.h"
#include "probe_matcher.h"

namespace bpftrace::ast {

void FieldAnalyser::visit(Identifier &identifier)
{
  bpftrace_.btf_set_.insert(identifier.ident);
}

void FieldAnalyser::visit(Builtin &builtin)
{
  std::string builtin_type;
  sized_type_ = CreateNone();
  if (builtin.ident == "ctx") {
    if (!probe_)
      return;
    switch (prog_type_) {
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
      builtin_type = "struct bpf_iter__" + attach_func_;
  } else if (builtin.ident == "curtask") {
    builtin_type = "struct task_struct";
  } else if (builtin.ident == "args") {
    if (!probe_)
      return;
    resolve_args(*probe_);
    has_builtin_args_ = true;
    return;
  } else if (builtin.ident == "retval") {
    if (!probe_)
      return;
    resolve_args(*probe_);

    auto arg = bpftrace_.structs.GetProbeArg(*probe_, RETVAL_FIELD_NAME);
    if (arg)
      sized_type_ = arg->type;
    return;
  }

  if (bpftrace_.has_btf_data())
    sized_type_ = bpftrace_.btf_->get_stype(builtin_type);
}

void FieldAnalyser::visit(Map &map)
{
  visit(map.key_expr);

  auto it = var_types_.find(map.ident);
  if (it != var_types_.end())
    sized_type_ = it->second;
}

void FieldAnalyser::visit(Variable &var)
{
  auto it = var_types_.find(var.ident);
  if (it != var_types_.end())
    sized_type_ = it->second;
}

void FieldAnalyser::visit(FieldAccess &acc)
{
  has_builtin_args_ = false;

  visit(acc.expr);

  if (has_builtin_args_) {
    auto arg = bpftrace_.structs.GetProbeArg(*probe_, acc.field);
    if (arg)
      sized_type_ = arg->type;

    has_builtin_args_ = false;
  } else if (sized_type_.IsRecordTy()) {
    SizedType field_type = CreateNone();
    if (sized_type_.HasField(acc.field))
      field_type = sized_type_.GetField(acc.field).type;

    if (!field_type.IsNoneTy()) {
      sized_type_ = field_type;
    } else if (bpftrace_.has_btf_data()) {
      // If the struct type or the field type has not been resolved, add the
      // type to the BTF set to let ClangParser resolve it
      bpftrace_.btf_set_.insert(sized_type_.GetName());
      auto field_type_name = bpftrace_.btf_->type_of(sized_type_.GetName(),
                                                     acc.field);
      bpftrace_.btf_set_.insert(field_type_name);
    }
  }
}

void FieldAnalyser::visit(ArrayAccess &arr)
{
  visit(arr.indexpr);
  visit(arr.expr);
  if (sized_type_.IsPtrTy()) {
    sized_type_ = *sized_type_.GetPointeeTy();
    resolve_fields(sized_type_);
  } else if (sized_type_.IsArrayTy()) {
    sized_type_ = *sized_type_.GetElementTy();
    resolve_fields(sized_type_);
  }
}

void FieldAnalyser::visit(Cast &cast)
{
  visit(cast.expr);
  resolve_type(cast.type);
}

void FieldAnalyser::visit(Sizeof &szof)
{
  visit(szof.expr);
  resolve_type(szof.argtype);
}

void FieldAnalyser::visit(Offsetof &offof)
{
  if (offof.expr)
    visit(*offof.expr);
  resolve_type(offof.record);
}

void FieldAnalyser::visit(AssignMapStatement &assignment)
{
  visit(assignment.map);
  visit(assignment.expr);
  var_types_.emplace(assignment.map->ident, sized_type_);
}

void FieldAnalyser::visit(AssignVarStatement &assignment)
{
  visit(assignment.expr);
  var_types_.emplace(assignment.var->ident, sized_type_);
}

void FieldAnalyser::visit(Unop &unop)
{
  visit(unop.expr);
  if (unop.op == Operator::MUL && sized_type_.IsPtrTy()) {
    // Need a temporary to prevent UAF from self-referential assignment
    auto tmp = *sized_type_.GetPointeeTy();
    sized_type_ = std::move(tmp);
    resolve_fields(sized_type_);
  }
}

void FieldAnalyser::resolve_args(Probe &probe)
{
  for (auto *ap : probe.attach_points) {
    // load probe arguments into a special record type "struct <probename>_args"
    Struct probe_args;

    auto probe_type = probetype(ap->provider);
    if (probe_type != ProbeType::fentry && probe_type != ProbeType::fexit &&
        probe_type != ProbeType::uprobe)
      continue;

    if (ap->expansion != ExpansionType::NONE) {
      std::set<std::string> matches;

      // Find all the matches for the wildcard..
      try {
        matches = bpftrace_.probe_matcher_->get_matches_for_ap(*ap);
      } catch (const WildcardException &e) {
        LOG(ERROR) << e.what();
        return;
      }

      // ... and check if they share same arguments.

      Struct ap_args;
      for (auto &match : matches) {
        // Both uprobes and fentry have a target (binary for uprobes, kernel
        // module for fentry).
        std::string func = match;
        std::string target = erase_prefix(func);

        // Trying to attach to multiple fentry. If some of them fails on
        // argument resolution, do not fail hard, just print a warning and
        // continue with other functions.
        if (probe_type == ProbeType::fentry || probe_type == ProbeType::fexit) {
          std::string err;
          auto maybe_ap_args = bpftrace_.btf_->resolve_args(
              func, probe_type == ProbeType::fexit, err);
          if (!maybe_ap_args.has_value()) {
            LOG(WARNING) << "fentry:" << ap->func << ": " << err;
            continue;
          }
          ap_args = std::move(*maybe_ap_args);
        } else // uprobe
        {
          Dwarf *dwarf = bpftrace_.get_dwarf(target);
          if (dwarf)
            ap_args = dwarf->resolve_args(func);
          else
            LOG(WARNING, ap->loc, err_) << "No debuginfo found for " << target;
        }

        if (probe_args.size == -1)
          probe_args = ap_args;
        else if (ap_args != probe_args) {
          LOG(ERROR, ap->loc, err_)
              << "Probe has attach points with mixed arguments";
          break;
        }
      }
    } else {
      // Resolving args for an explicit function failed, print an error and fail
      if (probe_type == ProbeType::fentry || probe_type == ProbeType::fexit) {
        std::string err;
        auto maybe_probe_args = bpftrace_.btf_->resolve_args(
            ap->func, probe_type == ProbeType::fexit, err);
        if (!maybe_probe_args.has_value()) {
          LOG(ERROR, ap->loc, err_) << "fentry:" << ap->func << ": " << err;
          return;
        }
        probe_args = std::move(*maybe_probe_args);
      } else // uprobe
      {
        Dwarf *dwarf = bpftrace_.get_dwarf(ap->target);
        if (dwarf)
          probe_args = dwarf->resolve_args(ap->func);
        else {
          LOG(WARNING, ap->loc, err_)
              << "No debuginfo found for " << ap->target;
        }
        if (static_cast<int>(probe_args.fields.size()) >
            (arch::max_arg() + 1)) {
          LOG(ERROR, ap->loc, err_) << "\'args\' builtin is not supported for "
                                       "probes with stack-passed arguments.";
        }
      }
    }

    // check if we already stored arguments for this probe
    auto args = bpftrace_.structs.Lookup(probe.args_typename()).lock();
    if (args && *args != probe_args) {
      // we did, and it's different...trigger the error
      LOG(ERROR, ap->loc, err_)
          << "Probe has attach points with mixed arguments";
    } else {
      // store/save args for each ap for later processing
      bpftrace_.structs.Add(probe.args_typename(), std::move(probe_args));
    }
  }
  return;
}

void FieldAnalyser::resolve_fields(SizedType &type)
{
  if (!type.IsRecordTy())
    return;

  if (probe_) {
    for (auto &ap : probe_->attach_points)
      if (Dwarf *dwarf = bpftrace_.get_dwarf(*ap))
        dwarf->resolve_fields(type);
  }

  if (type.GetFieldCount() == 0 && bpftrace_.has_btf_data())
    bpftrace_.btf_->resolve_fields(type);
}

void FieldAnalyser::resolve_type(SizedType &type)
{
  sized_type_ = CreateNone();

  const SizedType *inner_type = &type;
  while (inner_type->IsPtrTy())
    inner_type = inner_type->GetPointeeTy();
  if (!inner_type->IsRecordTy())
    return;
  auto name = inner_type->GetName();

  if (probe_) {
    for (auto &ap : probe_->attach_points)
      if (Dwarf *dwarf = bpftrace_.get_dwarf(*ap))
        sized_type_ = dwarf->get_stype(name);
  }

  if (sized_type_.IsNoneTy() && bpftrace_.has_btf_data())
    sized_type_ = bpftrace_.btf_->get_stype(name);

  // Could not resolve destination type - let ClangParser do it
  if (sized_type_.IsNoneTy())
    bpftrace_.btf_set_.insert(name);
}

void FieldAnalyser::visit(Probe &probe)
{
  probe_ = &probe;

  for (AttachPoint *ap : probe.attach_points) {
    probe_type_ = probetype(ap->provider);
    prog_type_ = progtype(probe_type_);
    attach_func_ = ap->func;
  }
  if (probe.pred) {
    visit(probe.pred);
  }
  visit(probe.block);
}

void FieldAnalyser::visit(Subprog &subprog)
{
  probe_ = nullptr;
  visit(subprog.stmts);
}

int FieldAnalyser::analyse()
{
  visit(ctx_.root);

  std::string errors = err_.str();
  if (!errors.empty()) {
    out_ << errors;
    return 1;
  }

  return 0;
}

} // namespace bpftrace::ast
