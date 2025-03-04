#pragma once

#include <string>

#include "ast/pass_manager.h"
#include "ast/visitor.h"
#include "bpftrace.h"

namespace libbpf {
#include "libbpf/bpf.h"
} // namespace libbpf

namespace bpftrace::ast {

class FieldAnalyser : public Visitor<FieldAnalyser> {
public:
  explicit FieldAnalyser(BPFtrace &bpftrace)
      : bpftrace_(bpftrace), prog_type_(libbpf::BPF_PROG_TYPE_UNSPEC)
  {
  }

  using Visitor<FieldAnalyser>::visit;
  void visit(Identifier &identifier);
  void visit(Builtin &builtin);
  void visit(Map &map);
  void visit(Variable &var);
  void visit(FieldAccess &acc);
  void visit(ArrayAccess &arr);
  void visit(Cast &cast);
  void visit(Sizeof &szof);
  void visit(Offsetof &offof);
  void visit(AssignMapStatement &assignment);
  void visit(AssignVarStatement &assignment);
  void visit(Unop &unop);
  void visit(Probe &probe);
  void visit(Subprog &subprog);

private:
  void resolve_args(Probe &probe);
  void resolve_fields(SizedType &type);
  void resolve_type(SizedType &type);

  ProbeType probe_type_;
  std::string attach_func_;
  SizedType sized_type_;
  BPFtrace &bpftrace_;
  libbpf::bpf_prog_type prog_type_;
  bool has_builtin_args_;
  Probe *probe_ = nullptr;

  std::map<std::string, SizedType> var_types_;
};

Pass CreateFieldAnalyserPass();

} // namespace bpftrace::ast
