#pragma once

#include "bpftrace.h"
#include "visitors.h"
#include <iostream>
#include <string>
#include <unordered_set>

namespace bpftrace {
namespace ast {

class FieldAnalyser : public Visitor
{
public:
  explicit FieldAnalyser(Node *root,
                         BPFtrace &bpftrace,
                         std::ostream &out = std::cerr)
      : root_(root),
        type_(""),
        bpftrace_(bpftrace),
        prog_type_(BPF_PROG_TYPE_UNSPEC),
        out_(out)
  { }

  void visit(Identifier &identifier) override;
  void visit(Builtin &builtin) override;
  void visit(Map &map) override;
  void visit(Variable &var) override;
  void visit(FieldAccess &acc) override;
  void visit(Cast &cast) override;
  void visit(AssignMapStatement &assignment) override;
  void visit(AssignVarStatement &assignment) override;
  void visit(Probe &probe) override;

  int analyse();

private:
  bool resolve_args(Probe &probe);
  bool compare_args(const ProbeArgs &args1, const ProbeArgs &args2);

  Node *root_;
  ProbeType probe_type_;
  std::string attach_func_;
  std::string    type_;
  BPFtrace      &bpftrace_;
  bpf_prog_type  prog_type_;
  bool           has_builtin_args_;
  Probe         *probe_;

  std::ostream       &out_;
  std::ostringstream  err_;

  ProbeArgs ap_args_;
  std::map<std::string, std::string> var_types_;
};

} // namespace ast
} // namespace bpftrace
