#pragma once

#include <iostream>
#include <sstream>
#include <unordered_set>

#include "ast/pass_manager.h"
#include "ast/visitor.h"
#include "bpffeature.h"
#include "bpftrace.h"
#include "collect_nodes.h"
#include "config.h"
#include "types.h"

namespace bpftrace {
namespace ast {

struct variable {
  SizedType type;
  bool can_resize;
  bool was_assigned;
};

class PassTracker {
public:
  void mark_final_pass()
  {
    is_final_pass_ = true;
  }
  bool is_final_pass() const
  {
    return is_final_pass_;
  }
  void inc_num_unresolved()
  {
    num_unresolved_++;
  }
  void reset_num_unresolved()
  {
    num_unresolved_ = 0;
  }
  int get_num_unresolved() const
  {
    return num_unresolved_;
  }
  int get_num_passes() const
  {
    return num_passes_;
  }
  void inc_num_passes()
  {
    num_passes_++;
  }

private:
  bool is_final_pass_ = false;
  int num_unresolved_ = 0;
  int num_passes_ = 1;
};

class SemanticAnalyser : public Visitor<SemanticAnalyser> {
public:
  explicit SemanticAnalyser(ASTContext &ctx,
                            BPFtrace &bpftrace,
                            std::ostream &out = std::cerr,
                            bool has_child = true,
                            bool listing = false)
      : Visitor<SemanticAnalyser>(ctx),
        bpftrace_(bpftrace),
        out_(out),
        listing_(listing),
        has_child_(has_child)
  {
  }

  explicit SemanticAnalyser(ASTContext &ctx, BPFtrace &bpftrace, bool has_child)
      : SemanticAnalyser(ctx, bpftrace, std::cerr, has_child)
  {
  }

  explicit SemanticAnalyser(ASTContext &ctx,
                            BPFtrace &bpftrace,
                            bool has_child,
                            bool listing)
      : SemanticAnalyser(ctx, bpftrace, std::cerr, has_child, listing)
  {
  }

  using Visitor<SemanticAnalyser>::visit;
  void visit(Integer &integer);
  void visit(PositionalParameter &param);
  void visit(String &string);
  void visit(StackMode &mode);
  void visit(Identifier &identifier);
  void visit(Builtin &builtin);
  void visit(Call &call);
  void visit(Sizeof &szof);
  void visit(Offsetof &offof);
  void visit(Map &map);
  void visit(Variable &var);
  void visit(Binop &binop);
  void visit(Unop &unop);
  void visit(While &while_block);
  void visit(For &f);
  void visit(Jump &jump);
  void visit(Ternary &ternary);
  void visit(FieldAccess &acc);
  void visit(ArrayAccess &arr);
  void visit(Cast &cast);
  void visit(Tuple &tuple);
  void visit(ExprStatement &expr);
  void visit(AssignMapStatement &assignment);
  void visit(AssignVarStatement &assignment);
  void visit(AssignConfigVarStatement &assignment);
  void visit(VarDeclStatement &decl);
  void visit(If &if_node);
  void visit(Unroll &unroll);
  void visit(Predicate &pred);
  void visit(AttachPoint &ap);
  void visit(Probe &probe);
  void visit(Config &config);
  void visit(Block &block);
  void visit(Subprog &subprog);

  int analyse();

private:
  PassTracker pass_tracker_;
  BPFtrace &bpftrace_;
  std::ostream &out_;
  std::ostringstream err_;
  bool listing_;

  bool is_final_pass() const;
  bool is_first_pass() const;

  bool check_assignment(const Call &call,
                        bool want_map,
                        bool want_var,
                        bool want_map_key);
  [[nodiscard]] bool check_nargs(const Call &call, size_t expected_nargs);
  [[nodiscard]] bool check_varargs(const Call &call,
                                   size_t min_nargs,
                                   size_t max_nargs);
  bool check_arg(const Call &call,
                 Type type,
                 int arg_num,
                 bool want_literal = false,
                 bool fail = true);
  bool check_symbol(const Call &call, int arg_num);
  bool check_available(const Call &call, const AttachPoint &ap);

  void check_stack_call(Call &call, bool kernel);

  Probe *get_probe(const location &loc, std::string name = "");

  bool is_valid_assignment(const Expression *target, const Expression *expr);
  SizedType *get_map_type(const Map &map);
  SizedType *get_map_key_type(const Map &map);
  void assign_map_type(const Map &map, const SizedType &type);
  SizedType create_key_type(const SizedType &expr_type, const location &loc);
  void update_current_key(SizedType &current_key_type,
                          const SizedType &new_key_type);
  void validate_new_key(const SizedType &current_key_type,
                        const SizedType &new_key_type,
                        const std::string &map_ident,
                        const location &loc);
  bool update_string_size(SizedType &type, const SizedType &new_type);
  SizedType create_merged_tuple(const SizedType &blah_type,
                                const SizedType &prev_type);
  void validate_map_key(const SizedType &key, const location &loc);
  void resolve_struct_type(SizedType &type, const location &loc);

  void builtin_args_tracepoint(AttachPoint *attach_point, Builtin &builtin);
  ProbeType single_provider_type(Probe *probe);
  AddrSpace find_addrspace(ProbeType pt);

  void binop_ptr(Binop &op);
  void binop_int(Binop &op);
  void binop_array(Binop &op);
  Expression *dereference_if_needed(Expression *expr);

  bool has_error() const;
  bool in_loop(void)
  {
    return loop_depth_ > 0;
  };
  void accept_statements(StatementList &stmts);

  // At the moment we iterate over the stack from top to bottom as variable
  // shadowing is not supported.
  std::vector<Node *> scope_stack_;
  Node *top_level_node_ = nullptr;

  // Holds the function currently being visited by this SemanticAnalyser.
  std::string func_;
  // Holds the function argument index currently being visited by this
  // SemanticAnalyser.
  int func_arg_idx_ = -1;

  variable *find_variable(const std::string &var_ident);
  Node *find_variable_scope(const std::string &var_ident);

  std::map<Node *, std::map<std::string, variable>> variables_;
  std::map<Node *, std::map<std::string, location>> variable_decls_;
  std::map<Node *, CollectNodes<Variable>> for_vars_referenced_;
  std::map<std::string, SizedType> map_val_;
  std::map<std::string, SizedType> map_key_;

  uint32_t loop_depth_ = 0;
  bool has_begin_probe_ = false;
  bool has_end_probe_ = false;
  bool has_child_ = false;
  bool has_pos_param_ = false;
};

Pass CreateSemanticPass();

} // namespace ast
} // namespace bpftrace
