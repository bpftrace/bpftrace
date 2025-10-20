#include <bpf/bpf.h>
#include <cassert>

#include "ast/passes/field_analyser.h"
#include "ast/visitor.h"
#include "bpftrace.h"
#include "dwarf_parser.h"
#include "probe_matcher.h"

namespace bpftrace::ast {

namespace {

class FieldAnalyser : public Visitor<FieldAnalyser> {
public:
  explicit FieldAnalyser(BPFtrace &bpftrace) : bpftrace_(bpftrace) {};

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

  SizedType sized_type_;
  BPFtrace &bpftrace_;
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
  // For ctx and other builtins that have types set by the context resolver,
  // use those types. They may not yet be complete (waiting for clang to parse
  // the specific context types), but they are already set.
  if (!builtin.builtin_type.IsNoneTy()) {
    sized_type_ = builtin.builtin_type;
  }
}

void FieldAnalyser::visit(Map &map)
{
  auto it = var_types_.find(map.ident);
  if (it != var_types_.end()) {
    sized_type_ = it->second;
  } else {
    sized_type_ = CreateNone();
  }
}

void FieldAnalyser::visit(Variable &var)
{
  auto it = var_types_.find(var.ident);
  if (it != var_types_.end()) {
    sized_type_ = it->second;
  } else {
    sized_type_ = CreateNone();
  }
}

void FieldAnalyser::visit(FieldAccess &acc)
{
  visit(acc.expr);

  // Automatically resolve through pointers and arrays to ensure
  // nested structs get their fields resolved.
  while (sized_type_.IsPtrTy()) {
    sized_type_ = sized_type_.GetPointeeTy();
  }

  // Resolve as long as it is a structure.
  if (sized_type_.IsCStructTy()) {
    resolve_fields(sized_type_);
    if (sized_type_.HasField(acc.field)) {
      sized_type_ = sized_type_.GetField(acc.field).type;
      return; // The type will already be set.    }
    }

    // These no type, so we can't resolve.
    sized_type_ = CreateNone();
  }
}

void FieldAnalyser::visit(ArrayAccess &arr)
{
  visit(arr.indexpr);
  visit(arr.expr);

  if (sized_type_.IsPtrTy()) {
    sized_type_ = sized_type_.GetPointeeTy();
  } else if (sized_type_.IsArrayTy()) {
    sized_type_ = sized_type_.GetElementTy();
  } else {
    sized_type_ = CreateNone();
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
    // Need a temporary to prevent UAF from self-referential assignment.
    sized_type_ = sized_type_.GetPointeeTy();
  }
}

void FieldAnalyser::resolve_fields(SizedType &type)
{
  if (!type.IsCStructTy())
    return;

  if (probe_) {
    for (auto &ap : probe_->attach_points)
      if (Dwarf *dwarf = bpftrace_.get_dwarf(*ap))
        dwarf->resolve_fields(type);
  }

  if (type.GetFieldCount() == 0) {
    bpftrace_.btf_->resolve_fields(type);
  }
}

void FieldAnalyser::resolve_type(SizedType &type)
{
  SizedType inner_type = type;
  while (inner_type.IsPtrTy())
    inner_type = inner_type.GetPointeeTy();
  if (!inner_type.IsCStructTy() && !inner_type.IsEnumTy()) {
    sized_type_ = type;
    return; // Not a struct or enum, so can't resolve.
  }

  const auto &name = inner_type.GetName();

  SizedType resolved_type = CreateNone();
  if (probe_) {
    for (auto &ap : probe_->attach_points)
      if (Dwarf *dwarf = bpftrace_.get_dwarf(*ap))
        resolved_type = dwarf->get_stype(name);
  }

  if (resolved_type.IsNoneTy()) {
    resolved_type = bpftrace_.btf_->get_stype(name);
  }

  // Could not resolve destination type.
  if (resolved_type.IsNoneTy())
    bpftrace_.btf_set_.insert(name);

  // Always set sized_type_ to the cast type
  sized_type_ = resolved_type;
}

void FieldAnalyser::visit(Probe &probe)
{
  probe_ = &probe;
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
