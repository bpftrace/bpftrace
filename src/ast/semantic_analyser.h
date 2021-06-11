#pragma once

#include <iostream>
#include <sstream>
#include <unordered_set>

#include "bpffeature.h"
#include "bpftrace.h"
#include "map.h"
#include "pass_manager.h"
#include "types.h"
#include "visitors.h"

namespace bpftrace {
namespace ast {

class SemanticAnalyser : public Visitor
{
public:
  explicit SemanticAnalyser(Node *root,
                            BPFtrace &bpftrace,
                            std::ostream &out = std::cerr,
                            bool has_child = true,
                            bool listing = false)
      : root_(root),
        bpftrace_(bpftrace),
        out_(out),
        listing_(listing),
        has_child_(has_child)
  {
  }

  explicit SemanticAnalyser(Node *root, BPFtrace &bpftrace, bool has_child)
      : SemanticAnalyser(root, bpftrace, std::cerr, has_child)
  {
  }

  explicit SemanticAnalyser(Node *root,
                            BPFtrace &bpftrace,
                            bool has_child,
                            bool listing)
      : SemanticAnalyser(root, bpftrace, std::cerr, has_child, listing)
  {
  }

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
  void visit(While &while_block) override;
  void visit(Jump &jump) override;
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
  void visit(Predicate &pred) override;
  void visit(AttachPoint &ap) override;
  void visit(Probe &probe) override;
  void visit(Program &program) override;

  int analyse();

private:
  Node *root_ = nullptr;
  BPFtrace &bpftrace_;
  std::ostream &out_;
  std::ostringstream err_;
  int pass_;
  const int num_passes_ = 10;
  bool listing_;

  bool is_final_pass() const;

  bool check_assignment(const Call &call, bool want_map, bool want_var, bool want_map_key);
  bool check_nargs(const Call &call, size_t expected_nargs);
  bool check_varargs(const Call &call, size_t min_nargs, size_t max_nargs);
  bool check_arg(const Call &call,
                 Type type,
                 int arg_num,
                 bool want_literal = false,
                 bool fail = true);
  bool check_symbol(const Call &call, int arg_num);
  bool check_available(const Call &call, const AttachPoint &ap);

  void check_stack_call(Call &call, bool kernel);

  void assign_map_type(const Map &map, const SizedType &type);
  void update_assign_map_type(const Map &map,
                              SizedType &type,
                              const SizedType &new_type);

  void builtin_args_tracepoint(AttachPoint *attach_point, Builtin &builtin);
  ProbeType single_provider_type(void);
  AddrSpace find_addrspace(ProbeType pt);

  void binop_int(Binop &op);

  bool in_loop(void)
  {
    return loop_depth_ > 0;
  };
  void accept_statements(StatementList *stmts);

  Probe *probe_;

  // Holds the function currently being visited by this SemanticAnalyser.
  std::string func_;
  // Holds the function argument index currently being visited by this
  // SemanticAnalyser.
  int func_arg_idx_ = -1;

  std::map<std::string, SizedType> variable_val_;
  std::map<std::string, SizedType> map_val_;
  std::map<std::string, MapKey> map_key_;
  std::map<std::string, SizedType> ap_args_;

  uint32_t loop_depth_ = 0;
  bool has_begin_probe_ = false;
  bool has_end_probe_ = false;
  bool has_child_ = false;
  bool has_pos_param_ = false;
};

Pass CreateSemanticPass();
} // namespace ast
} // namespace bpftrace
