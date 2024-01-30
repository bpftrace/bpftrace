#pragma once

#include <iostream>
#include <string>
#include <unordered_set>

#include "ast/visitors.h"
#include "bpftrace.h"

namespace libbpf {
#include "libbpf/bpf.h"
} // namespace libbpf

namespace bpftrace {
namespace ast {

class FieldAnalyser : public Visitor {
public:
  explicit FieldAnalyser(Node *root,
                         BPFtrace &bpftrace,
                         std::ostream &out = std::cerr)
      : root_(root),
        bpftrace_(bpftrace),
        prog_type_(libbpf::BPF_PROG_TYPE_UNSPEC),
        out_(out)
  {
  }

  void visit(Identifier &identifier) override;
  void visit(Builtin &builtin) override;
  void visit(Map &map) override;
  void visit(Variable &var) override;
  void visit(FieldAccess &acc) override;
  void visit(Cast &cast) override;
  void visit(Sizeof &szof) override;
  void visit(Offsetof &ofof) override;
  void visit(AssignMapStatement &assignment) override;
  void visit(AssignVarStatement &assignment) override;
  void visit(Unop &unop) override;
  void visit(Probe &probe) override;

  int analyse();

private:
  bool resolve_args(Probe &probe);
  void resolve_fields(SizedType &type);
  void resolve_type(SizedType &type);

  Node *root_;
  ProbeType probe_type_;
  std::string attach_func_;
  SizedType sized_type_;
  BPFtrace &bpftrace_;
  libbpf::bpf_prog_type prog_type_;
  bool has_builtin_args_;
  Probe *probe_;

  std::ostream &out_;
  std::ostringstream err_;

  std::map<std::string, SizedType> var_types_;
};

} // namespace ast
} // namespace bpftrace
