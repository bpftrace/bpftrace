#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "diagnostic.h"
#include "types.h"
#include "usdt.h"
#include "utils.h"

namespace bpftrace {
namespace ast {

class ASTContext;

enum class JumpType {
  INVALID = 0,
  RETURN,
  CONTINUE,
  BREAK,
};

enum class Operator {
  INVALID = 0,
  ASSIGN,
  EQ,
  NE,
  LE,
  GE,
  LEFT,
  RIGHT,
  LT,
  GT,
  LAND,
  LOR,
  PLUS,
  INCREMENT,
  DECREMENT,
  MINUS,
  MUL,
  DIV,
  MOD,
  BAND,
  BOR,
  BXOR,
  LNOT,
  BNOT,
};

// There are 2 kinds of attach point expansion:
// - full expansion  - separate LLVM function is generated for each match
// - multi expansion - one LLVM function and BPF program is generated for all
//                     matches, the list of expanded functions is attached to
//                     the BPF program using the k(u)probe.multi mechanism
enum class ExpansionType {
  NONE,
  FULL,
  MULTI,
};

class Node {
public:
  Node(Diagnostics &d, location loc);
  virtual ~Node() = default;

  Node(const Node &) = delete;
  Node &operator=(const Node &) = delete;
  Node(Node &&) = delete;
  Node &operator=(Node &&) = delete;

  template <typename... Args>
  Diagnostic &addError(Args &...args) const
  {
    if constexpr (sizeof...(Args) == 0) {
      return diagnostics_.addError(loc);
    } else {
      return diagnostics_.addError(loc + (args.loc + ...));
    }
  }
  template <typename... Args>
  Diagnostic &addWarning(Args &...args) const
  {
    if constexpr (sizeof...(Args) == 0) {
      return diagnostics_.addWarning(loc);
    } else {
      return diagnostics_.addWarning(loc + (args.loc + ...));
    }
  }

private:
  Diagnostics &diagnostics_;

public:
  // This is temporarily accessible by other classes because we don't have a
  // clear `clone` operation at this time. Eventually this should be made
  // private and we should rely on a clear model for cloning nodes.
  location loc;
};

class Map;
class Variable;
class Expression : public Node {
public:
  Expression(Diagnostics &d, location loc) : Node(d, loc) {};
  virtual ~Expression() = default;

  SizedType type;
  Map *key_for_map = nullptr;
  Map *map = nullptr;      // Only set when this expression is assigned to a map
  Variable *var = nullptr; // Set when this expression is assigned to a variable
  bool is_literal = false;
  bool is_variable = false;
  bool is_map = false;
};
using ExpressionList = std::vector<Expression *>;

class Integer : public Expression {
public:
  explicit Integer(Diagnostics &d,
                   int64_t n,
                   location loc,
                   bool is_negative = true);

  int64_t n;
  bool is_negative;
};

class PositionalParameter : public Expression {
public:
  explicit PositionalParameter(Diagnostics &d,
                               PositionalParameterType ptype,
                               long n,
                               location loc);

  PositionalParameterType ptype;
  long n;
  bool is_in_str = false;
};

class String : public Expression {
public:
  explicit String(Diagnostics &d, const std::string &str, location loc);

  std::string str;
};

class StackMode : public Expression {
public:
  explicit StackMode(Diagnostics &d, const std::string &mode, location loc);

  std::string mode;
};

class Identifier : public Expression {
public:
  explicit Identifier(Diagnostics &d, const std::string &ident, location loc);

  std::string ident;
};

class Builtin : public Expression {
public:
  explicit Builtin(Diagnostics &d, const std::string &ident, location loc);

  std::string ident;
  int probe_id;

  // Check if the builtin is 'arg0' - 'arg9'
  bool is_argx() const
  {
    return !ident.compare(0, 3, "arg") && ident.size() == 4 &&
           ident.at(3) >= '0' && ident.at(3) <= '9';
  }
};

class Call : public Expression {
public:
  explicit Call(Diagnostics &d, const std::string &func, location loc);
  Call(Diagnostics &d,
       const std::string &func,
       ExpressionList &&vargs,
       location loc);

  std::string func;
  ExpressionList vargs;
};

class Sizeof : public Expression {
public:
  Sizeof(Diagnostics &d, SizedType type, location loc);
  Sizeof(Diagnostics &d, Expression *expr, location loc);

  Expression *expr = nullptr;
  SizedType argtype;
};

class Offsetof : public Expression {
public:
  Offsetof(Diagnostics &d,
           SizedType record,
           std::vector<std::string> &field,
           location loc);
  Offsetof(Diagnostics &d,
           Expression *expr,
           std::vector<std::string> &field,
           location loc);

  SizedType record;
  Expression *expr = nullptr;
  std::vector<std::string> field;
};

class Map : public Expression {
public:
  explicit Map(Diagnostics &d, const std::string &ident, location loc);
  Map(Diagnostics &d, const std::string &ident, Expression &expr, location loc);

  std::string ident;
  Expression *key_expr = nullptr;
  SizedType key_type;
  bool skip_key_validation = false;
  // This is for a feature check on reading per-cpu maps
  // which involve calling map_lookup_percpu_elem
  // https://github.com/bpftrace/bpftrace/issues/3755
  bool is_read = true;
};

class Variable : public Expression {
public:
  explicit Variable(Diagnostics &d, const std::string &ident, location loc);

  std::string ident;
};

class Binop : public Expression {
public:
  Binop(Diagnostics &d,
        Expression *left,
        Operator op,
        Expression *right,
        location loc);

  Expression *left = nullptr;
  Expression *right = nullptr;
  Operator op;
};

class Unop : public Expression {
public:
  Unop(Diagnostics &d,
       Operator op,
       Expression *expr,
       bool is_post_op,
       location loc);

  Expression *expr = nullptr;
  Operator op;
  bool is_post_op;
};

class FieldAccess : public Expression {
public:
  FieldAccess(Diagnostics &d, Expression *expr, const std::string &field);
  FieldAccess(Diagnostics &d,
              Expression *expr,
              const std::string &field,
              location loc);
  FieldAccess(Diagnostics &d, Expression *expr, ssize_t index, location loc);

  Expression *expr = nullptr;
  std::string field;
  ssize_t index = -1;
};

class ArrayAccess : public Expression {
public:
  ArrayAccess(Diagnostics &d, Expression *expr, Expression *indexpr);
  ArrayAccess(Diagnostics &d,
              Expression *expr,
              Expression *indexpr,
              location loc);

  Expression *expr = nullptr;
  Expression *indexpr = nullptr;
};

class Cast : public Expression {
public:
  Cast(Diagnostics &d, SizedType type, Expression *expr, location loc);

  Expression *expr = nullptr;
};

class Tuple : public Expression {
public:
  Tuple(Diagnostics &d, ExpressionList &&elems, location loc);

  ExpressionList elems;
};

class Statement : public Node {
public:
  Statement(Diagnostics &d, location loc) : Node(d, loc) {};
};

using StatementList = std::vector<Statement *>;

class ExprStatement : public Statement {
public:
  explicit ExprStatement(Diagnostics &d, Expression *expr, location loc);

  Expression *expr = nullptr;
};

class VarDeclStatement : public Statement {
public:
  VarDeclStatement(Diagnostics &d, Variable *var, SizedType type, location loc);
  VarDeclStatement(Diagnostics &d, Variable *var, location loc);

  Variable *var = nullptr;
  bool set_type = false;
};

class AssignMapStatement : public Statement {
public:
  AssignMapStatement(Diagnostics &d, Map *map, Expression *expr, location loc);

  Map *map = nullptr;
  Expression *expr = nullptr;
};

class AssignVarStatement : public Statement {
public:
  AssignVarStatement(Diagnostics &d,
                     Variable *var,
                     Expression *expr,
                     location loc);
  AssignVarStatement(Diagnostics &d,
                     VarDeclStatement *var_decl_stmt,
                     Expression *expr,
                     location loc);

  VarDeclStatement *var_decl_stmt = nullptr;
  Variable *var = nullptr;
  Expression *expr = nullptr;
};

class AssignConfigVarStatement : public Statement {
public:
  AssignConfigVarStatement(Diagnostics &d,
                           const std::string &config_var,
                           Expression *expr,
                           location loc);

  std::string config_var;
  Expression *expr = nullptr;
};

class Block : public Statement {
public:
  Block(Diagnostics &d, StatementList &&stmts, location loc);

  StatementList stmts;
};

class If : public Statement {
public:
  If(Diagnostics &d,
     Expression *cond,
     Block *if_block,
     Block *else_block,
     location loc);

  Expression *cond = nullptr;
  Block *if_block = nullptr;
  Block *else_block = nullptr;
};

class Unroll : public Statement {
public:
  Unroll(Diagnostics &d, Expression *expr, Block *block, location loc);

  long int var = 0;
  Expression *expr = nullptr;
  Block *block = nullptr;
};

class Jump : public Statement {
public:
  Jump(Diagnostics &d, JumpType ident, Expression *return_value, location loc)
      : Statement(d, loc), ident(ident), return_value(return_value)
  {
  }
  Jump(Diagnostics &d, JumpType ident, location loc)
      : Statement(d, loc), ident(ident), return_value(nullptr)
  {
  }

  JumpType ident = JumpType::INVALID;
  Expression *return_value;
};

class Predicate : public Node {
public:
  explicit Predicate(Diagnostics &d, Expression *expr, location loc);

  Expression *expr = nullptr;
};

class Ternary : public Expression {
public:
  Ternary(Diagnostics &d,
          Expression *cond,
          Expression *left,
          Expression *right,
          location loc);

  Expression *cond = nullptr;
  Expression *left = nullptr;
  Expression *right = nullptr;
};

class While : public Statement {
public:
  While(Diagnostics &d, Expression *cond, Block *block, location loc)
      : Statement(d, loc), cond(cond), block(block)
  {
  }

  Expression *cond = nullptr;
  Block *block = nullptr;
};

class For : public Statement {
public:
  For(Diagnostics &d,
      Variable *decl,
      Expression *expr,
      StatementList &&stmts,
      location loc)
      : Statement(d, loc), decl(decl), expr(expr), stmts(std::move(stmts))
  {
  }

  Variable *decl = nullptr;
  Expression *expr = nullptr;
  StatementList stmts;
  SizedType ctx_type;
};

class Config : public Statement {
public:
  Config(Diagnostics &d, StatementList &&stmts, location loc)
      : Statement(d, loc), stmts(std::move(stmts))
  {
  }

  StatementList stmts;
};

class AttachPoint : public Node {
public:
  AttachPoint(Diagnostics &d,
              const std::string &raw_input,
              bool ignore_invalid,
              location loc);

  // Currently, the AST node itself is used to store metadata related to probe
  // expansion and attachment. This is done through `create_expansion_copy`
  // below.  Since the nodes are not currently copyable by default (this is
  // currently fraught, as nodes may have backreferences that are not updated
  // in these cases), these fields are copied manually. *Until this is fixed,
  // if you are adding new fields, be sure to update `create_expansion_copy`.

  // Raw, unparsed input from user, eg. kprobe:vfs_read
  std::string raw_input;

  std::string provider;
  std::string target;
  std::string lang; // for userspace probes, enable language-specific features
  std::string ns;
  std::string func;
  std::string pin;
  usdt_probe_entry usdt; // resolved USDT entry, used to support arguments with
                         // wildcard matches
  int64_t freq = 0;
  uint64_t len = 0;   // for watchpoint probes, the width of watched addr
  std::string mode;   // for watchpoint probes, the watch mode
  bool async = false; // for watchpoint probes, if it's an async watchpoint

  ExpansionType expansion = ExpansionType::NONE;

  uint64_t address = 0;
  uint64_t func_offset = 0;
  bool ignore_invalid = false;

  std::string name() const;

  AttachPoint &create_expansion_copy(ASTContext &ctx,
                                     const std::string &match) const;

  int index() const;
  void set_index(int index);

private:
  int index_ = 0;
};
using AttachPointList = std::vector<AttachPoint *>;

class Probe : public Node {
public:
  Probe(Diagnostics &d,
        AttachPointList &&attach_points,
        Predicate *pred,
        Block *block,
        location loc);

  AttachPointList attach_points;
  Predicate *pred = nullptr;
  Block *block = nullptr;

  std::string name() const;
  std::string args_typename() const;
  bool need_expansion = false;    // must build a BPF program per wildcard match
  int tp_args_structs_level = -1; // number of levels of structs that must
                                  // be imported/resolved for tracepoints

  int index() const;
  void set_index(int index);

  bool has_ap_of_probetype(ProbeType probe_type);

private:
  int index_ = 0;
};
using ProbeList = std::vector<Probe *>;

class SubprogArg : public Node {
public:
  SubprogArg(Diagnostics &d, std::string name, SizedType type, location loc);

  std::string name() const;
  SizedType type;

private:
  std::string name_;
};
using SubprogArgList = std::vector<SubprogArg *>;

class Subprog : public Node {
public:
  Subprog(Diagnostics &d,
          std::string name,
          SizedType return_type,
          SubprogArgList &&args,
          StatementList &&stmts,
          location loc);

  SubprogArgList args;
  SizedType return_type;
  StatementList stmts;

  std::string name() const;

private:
  std::string name_;
};
using SubprogList = std::vector<Subprog *>;

class Program : public Node {
public:
  Program(Diagnostics &d,
          const std::string &c_definitions,
          Config *config,
          SubprogList &&functions,
          ProbeList &&probes,
          location loc);

  std::string c_definitions;
  Config *config = nullptr;
  SubprogList functions;
  ProbeList probes;
};

std::string opstr(const Binop &binop);
std::string opstr(const Unop &unop);
std::string opstr(const Jump &jump);

SizedType ident_to_record(const std::string &ident, int pointer_level = 0);
SizedType ident_to_sized_type(const std::string &ident);

} // namespace ast
} // namespace bpftrace
