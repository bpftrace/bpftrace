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
  void visit(AttachPoint &ap) override;
  void visit(Probe &probe) override;

  int analyse();

private:
  void check_kfunc_args(void);
  bool resolve_args(AttachPoint &ap);
  bool compare_args(const std::map<std::string, SizedType>& args1,
                    const std::map<std::string, SizedType>& args2);

  Node *root_;
  ProbeType probe_type_;
  std::string attach_func_;
  std::string    type_;
  BPFtrace      &bpftrace_;
  bpf_prog_type  prog_type_;
  bool           has_builtin_args_;
  bool           has_mixed_args_;
  bool           has_kfunc_probe_;
  Probe         *probe_;
  location       mixed_args_loc_;

  std::ostream       &out_;
  std::ostringstream  err_;

  std::map<std::string, SizedType> ap_args_;
  std::map<std::string, std::string> var_types_;
};

} // namespace ast
} // namespace bpftrace
