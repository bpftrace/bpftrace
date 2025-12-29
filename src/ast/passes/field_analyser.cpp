#include <bpf/bpf.h>
#include <cassert>

#include "arch/arch.h"
#include "ast/passes/ap_probe_expansion.h"
#include "ast/passes/field_analyser.h"
#include "ast/visitor.h"
#include "bpftrace.h"
#include "dwarf_parser.h"
#include "probe_matcher.h"
#include "util/strings.h"

namespace bpftrace::ast {

namespace {

class FieldAnalyser : public Visitor<FieldAnalyser> {
public:
  explicit FieldAnalyser(BPFtrace &bpftrace) : bpftrace_(bpftrace)
  {
  }

  using Visitor<FieldAnalyser>::visit;
  void visit(Identifier &identifier);
  void visit(Builtin &builtin);
  void visit(Map &map);
  void visit(Variable &var);
  void visit(FieldAccess &acc);
  void visit(ArrayAccess &arr);
  void visit(MapAccess &acc);
  void visit(Sizeof &szof);
  void visit(Offsetof &offof);
  void visit(Typeof &typeof);
  void visit(AssignMapStatement &assignment);
  void visit(AssignVarStatement &assignment);
  void visit(Unop &unop);
  void visit(Probe &probe);
  void visit(Subprog &subprog);
  void visit(Cast &cast);

private:
  void resolve_fields(SizedType &type);
  void resolve_type(SizedType &type);

  ProbeType probe_type_;
  std::string attach_func_;
  SizedType sized_type_;
  BPFtrace &bpftrace_;
  bpf_prog_type prog_type_{ BPF_PROG_TYPE_UNSPEC };
  bool has_builtin_args_;
  Probe *probe_ = nullptr;

  std::map<std::string, SizedType> var_types_;
};

} // namespace

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
      case BPF_PROG_TYPE_KPROBE:
        builtin_type = "struct pt_regs";
        break;
      case BPF_PROG_TYPE_PERF_EVENT:
        builtin_type = "struct bpf_perf_event_data";
        break;
      default:
        break;
    }
    // For each iterator probe, the context is pointing to specific struct,
    // make them resolved and available
    if (probe_type_ == ProbeType::iter)
      builtin_type = "struct bpf_iter__" + attach_func_;
  } else if (builtin.ident == "__builtin_curtask") {
    builtin_type = "struct task_struct";
  } else if (builtin.ident == "args") {
    if (!probe_)
      return;
    has_builtin_args_ = true;
    return;
  } else if (builtin.ident == "__builtin_retval") {
    if (!probe_)
      return;

    const auto *arg = bpftrace_.structs.GetProbeArg(*probe_, RETVAL_FIELD_NAME);
    if (arg)
      sized_type_ = arg->type;
    return;
  }

  if (bpftrace_.has_btf_data())
    sized_type_ = bpftrace_.btf_->get_stype(builtin_type);
}

void FieldAnalyser::visit(Map &map)
{
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

  // Automatically resolve through pointers.
  while (sized_type_.IsPtrTy()) {
    auto tmp = *sized_type_.GetPointeeTy();
    sized_type_ = std::move(tmp);
    resolve_fields(sized_type_);
  }

  if (has_builtin_args_) {
    const auto *arg = bpftrace_.structs.GetProbeArg(*probe_, acc.field);
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

void FieldAnalyser::visit(MapAccess &acc)
{
  visit(acc.key);
  visit(acc.map); // Leaves sized_type_ as value type.
}

void FieldAnalyser::visit(Sizeof &szof)
{
  if (std::holds_alternative<SizedType>(szof.record)) {
    resolve_type(std::get<SizedType>(szof.record));
  } else {
    visit(szof.record);
  }
}

void FieldAnalyser::visit(Offsetof &offof)
{
  if (std::holds_alternative<SizedType>(offof.record)) {
    resolve_type(std::get<SizedType>(offof.record));
  } else {
    visit(offof.record);
  }
}

void FieldAnalyser::visit(Typeof &typeof)
{
  if (std::holds_alternative<SizedType>(typeof.record)) {
    resolve_type(std::get<SizedType>(typeof.record));
  } else {
    visit(typeof.record);
  }
}

void FieldAnalyser::visit(AssignMapStatement &assignment)
{
  visit(assignment.map_access);
  visit(assignment.expr);
  var_types_.emplace(assignment.map_access->map->ident, sized_type_);
}

void FieldAnalyser::visit(AssignVarStatement &assignment)
{
  visit(assignment.expr);
  var_types_.emplace(assignment.var()->ident, sized_type_);
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
  const auto &name = inner_type->GetName();

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
  visit(probe.block);
}

void FieldAnalyser::visit(Subprog &subprog)
{
  probe_ = nullptr;
  visit(subprog.block);
}

void FieldAnalyser::visit(Cast &cast)
{
  // N.B. Visit the expression first, so that fields can be resolved, but then
  // visit the type so that the returned sized_type_ is always the type.
  visit(cast.expr);
  visit(cast.typeof);
}

Pass CreateFieldAnalyserPass()
{
  auto fn = [](ASTContext &ast, BPFtrace &b) {
    FieldAnalyser analyser(b);
    analyser.visit(ast.root);
  };

  return Pass::create("FieldAnalyser", fn);
};

} // namespace bpftrace::ast
