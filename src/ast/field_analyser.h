#pragma once

#include "ast.h"
#include "bpftrace.h"
#include <iostream>
#include <string>
#include <unordered_set>

namespace bpftrace {
namespace ast {

class FieldAnalyser : public Visitor {
public:
  explicit FieldAnalyser(Node *root,
                         BPFtrace &bpftrace,
                         std::ostream &out = std::cerr)
      : type_(""),
        root_(root),
        bpftrace_(bpftrace),
        prog_type_(BPF_PROG_TYPE_UNSPEC),
        out_(out)
  { }

  void visit(Integer &integer) override;
  void visit(PositionalParameter &param) override;
  void visit(String &string) override;
  void visit(StackMode &mode) override;
  void visit(Identifier &identifier) override;
  void visit(Builtin &builtin) override;
  void visit(Call &call) override;
  void visit(Map &map) override;
  void visit(Variable &var) override;
  void visit(Binop &binop) override;
  void visit(Unop &unop) override;
  void visit(Ternary &ternary) override;
  void visit(FieldAccess &acc) override;
  void visit(ArrayAccess &arr) override;
  void visit(Cast &cast) override;
  void visit(Tuple &tuple) override;
  void visit(ExprStatement &expr) override;
  void visit(AssignMapStatement &assignment) override;
  void visit(AssignVarStatement &assignment) override;
  void visit(If &if_block) override;
  void visit(Unroll &unroll) override;
  void visit(While &while_block) override;
  void visit(Jump &jump) override;
  void visit(Predicate &pred) override;
  void visit(AttachPoint &ap) override;
  void visit(Probe &probe) override;
  void visit(Program &program) override;

  int analyse();

private:
  void check_kfunc_args(void);
  bool resolve_args(AttachPoint &ap);
  bool compare_args(const std::map<std::string, SizedType>& args1,
                    const std::map<std::string, SizedType>& args2);

  std::string    type_;
  Node          *root_;
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
