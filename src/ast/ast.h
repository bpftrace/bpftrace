#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "location.hh"
#include "mapkey.h"
#include "types.h"
#include "usdt.h"
#include "utils.h"

namespace bpftrace {
namespace ast {

class VisitorBase;

#define DEFINE_ACCEPT void accept(VisitorBase &v) override;

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
  Node() = default;
  Node(location loc) : loc(loc){};
  virtual ~Node() = default;

  Node(const Node &) = default;
  Node &operator=(const Node &) = delete;
  Node(Node &&) = delete;
  Node &operator=(Node &&) = delete;

  virtual void accept(VisitorBase &v) = 0;

  location loc;
};

class Map;
class Variable;
class Expression : public Node {
public:
  Expression() = default;
  Expression(location loc) : Node(loc){};
  virtual ~Expression() = default;

  Expression(const Expression &) = default;
  Expression &operator=(const Expression &) = delete;
  Expression(Expression &&) = delete;
  Expression &operator=(Expression &&) = delete;

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
  DEFINE_ACCEPT

  explicit Integer(int64_t n, location loc);

  int64_t n;

private:
  Integer(const Integer &other) = default;
};

class PositionalParameter : public Expression {
public:
  DEFINE_ACCEPT

  explicit PositionalParameter(PositionalParameterType ptype,
                               long n,
                               location loc);

  PositionalParameterType ptype;
  long n;
  bool is_in_str = false;

private:
  PositionalParameter(const PositionalParameter &other) = default;
};

class String : public Expression {
public:
  DEFINE_ACCEPT

  explicit String(const std::string &str, location loc);

  std::string str;

private:
  String(const String &other) = default;
};

class StackMode : public Expression {
public:
  DEFINE_ACCEPT

  explicit StackMode(const std::string &mode, location loc);

  std::string mode;

private:
  StackMode(const StackMode &other) = default;
};

class Identifier : public Expression {
public:
  DEFINE_ACCEPT

  explicit Identifier(const std::string &ident, location loc);

  std::string ident;

private:
  Identifier(const Identifier &other) = default;
};

class Builtin : public Expression {
public:
  DEFINE_ACCEPT

  explicit Builtin(const std::string &ident, location loc);

  std::string ident;
  int probe_id;

  // Check if the builtin is 'arg0' - 'arg9'
  bool is_argx() const
  {
    return !ident.compare(0, 3, "arg") && ident.size() == 4 &&
           ident.at(3) >= '0' && ident.at(3) <= '9';
  }

private:
  Builtin(const Builtin &other) = default;
};

class Call : public Expression {
public:
  DEFINE_ACCEPT

  explicit Call(const std::string &func, location loc);
  Call(const std::string &func, ExpressionList &&vargs, location loc);

  std::string func;
  ExpressionList vargs;

private:
  Call(const Call &other) = default;
};

class Sizeof : public Expression {
public:
  DEFINE_ACCEPT

  Sizeof(SizedType type, location loc);
  Sizeof(Expression *expr, location loc);

  Expression *expr = nullptr;
  SizedType argtype;

private:
  Sizeof(const Sizeof &other) = default;
};

class Offsetof : public Expression {
public:
  DEFINE_ACCEPT

  Offsetof(SizedType record, std::string &field, location loc);
  Offsetof(Expression *expr, std::string &field, location loc);

  SizedType record;
  Expression *expr = nullptr;
  std::string field;

private:
  Offsetof(const Offsetof &other) = default;
};

class Map : public Expression {
public:
  DEFINE_ACCEPT

  explicit Map(const std::string &ident, location loc);
  Map(const std::string &ident, ExpressionList &&vargs, location loc);

  std::string ident;
  MapKey key_type;
  ExpressionList vargs;
  bool skip_key_validation = false;

private:
  Map(const Map &other) = default;
};

class Variable : public Expression {
public:
  DEFINE_ACCEPT

  explicit Variable(const std::string &ident, location loc);

  std::string ident;

private:
  Variable(const Variable &other) = default;
};

class Binop : public Expression {
public:
  DEFINE_ACCEPT

  Binop(Expression *left, Operator op, Expression *right, location loc);

  Expression *left = nullptr;
  Expression *right = nullptr;
  Operator op;

private:
  Binop(const Binop &other) = default;
};

class Unop : public Expression {
public:
  DEFINE_ACCEPT

  Unop(Operator op, Expression *expr, location loc = location());
  Unop(Operator op,
       Expression *expr,
       bool is_post_op = false,
       location loc = location());

  Expression *expr = nullptr;
  Operator op;
  bool is_post_op;

private:
  Unop(const Unop &other) = default;
};

class FieldAccess : public Expression {
public:
  DEFINE_ACCEPT

  FieldAccess(Expression *expr, const std::string &field);
  FieldAccess(Expression *expr, const std::string &field, location loc);
  FieldAccess(Expression *expr, ssize_t index, location loc);

  Expression *expr = nullptr;
  std::string field;
  ssize_t index = -1;

private:
  FieldAccess(const FieldAccess &other) = default;
};

class ArrayAccess : public Expression {
public:
  DEFINE_ACCEPT

  ArrayAccess(Expression *expr, Expression *indexpr);
  ArrayAccess(Expression *expr, Expression *indexpr, location loc);

  Expression *expr = nullptr;
  Expression *indexpr = nullptr;

private:
  ArrayAccess(const ArrayAccess &other) = default;
};

class Cast : public Expression {
public:
  DEFINE_ACCEPT

  Cast(SizedType type, Expression *expr, location loc);

  Expression *expr = nullptr;

private:
  Cast(const Cast &other) = default;
};

class Tuple : public Expression {
public:
  DEFINE_ACCEPT

  Tuple(ExpressionList &&elems, location loc);

  ExpressionList elems;

private:
  Tuple(const Tuple &other) = default;
};

class Statement : public Node {
public:
  Statement() = default;
  Statement(location loc) : Node(loc){};
  virtual ~Statement() = default;

  Statement(const Statement &) = default;
  Statement &operator=(const Statement &) = delete;
  Statement(Statement &&) = delete;
  Statement &operator=(Statement &&) = delete;
};

using StatementList = std::vector<Statement *>;

class ExprStatement : public Statement {
public:
  DEFINE_ACCEPT

  explicit ExprStatement(Expression *expr, location loc);

  Expression *expr = nullptr;

private:
  ExprStatement(const ExprStatement &other) = default;
};

class AssignMapStatement : public Statement {
public:
  DEFINE_ACCEPT

  AssignMapStatement(Map *map, Expression *expr, location loc = location());

  Map *map = nullptr;
  Expression *expr = nullptr;

private:
  AssignMapStatement(const AssignMapStatement &other) = default;
};

class AssignVarStatement : public Statement {
public:
  DEFINE_ACCEPT

  AssignVarStatement(Variable *var,
                     Expression *expr,
                     location loc = location());

  Variable *var = nullptr;
  Expression *expr = nullptr;

private:
  AssignVarStatement(const AssignVarStatement &other) = default;
};

class AssignConfigVarStatement : public Statement {
public:
  DEFINE_ACCEPT

  AssignConfigVarStatement(const std::string &config_var,
                           Expression *expr,
                           location loc = location());

  std::string config_var;
  Expression *expr = nullptr;

private:
  AssignConfigVarStatement(const AssignConfigVarStatement &other) = default;
};

class If : public Statement {
public:
  DEFINE_ACCEPT

  If(Expression *cond, StatementList &&stmts);
  If(Expression *cond, StatementList &&stmts, StatementList &&else_stmts);

  Expression *cond = nullptr;
  StatementList stmts;
  StatementList else_stmts;

private:
  If(const If &other) = default;
};

class Unroll : public Statement {
public:
  DEFINE_ACCEPT

  Unroll(Expression *expr, StatementList &&stmts, location loc);

  long int var = 0;
  Expression *expr = nullptr;
  StatementList stmts;

private:
  Unroll(const Unroll &other) = default;
};

class Jump : public Statement {
public:
  DEFINE_ACCEPT

  Jump(JumpType ident, Expression *return_value, location loc = location())
      : Statement(loc), ident(ident), return_value(return_value)
  {
  }
  Jump(JumpType ident, location loc = location())
      : Statement(loc), ident(ident), return_value(nullptr)
  {
  }

  JumpType ident = JumpType::INVALID;
  Expression *return_value;

private:
  Jump(const Jump &other) = default;
};

class Predicate : public Node {
public:
  DEFINE_ACCEPT

  explicit Predicate(Expression *expr, location loc);

  Expression *expr = nullptr;

private:
  Predicate(const Predicate &other) = default;
};

class Ternary : public Expression {
public:
  DEFINE_ACCEPT

  Ternary(Expression *cond, Expression *left, Expression *right, location loc);

  Expression *cond = nullptr;
  Expression *left = nullptr;
  Expression *right = nullptr;
};

class While : public Statement {
public:
  DEFINE_ACCEPT

  While(Expression *cond, StatementList &&stmts, location loc)
      : Statement(loc), cond(cond), stmts(std::move(stmts))
  {
  }

  Expression *cond = nullptr;
  StatementList stmts;

private:
  While(const While &other) = default;
};

class For : public Statement {
public:
  DEFINE_ACCEPT

  For(Variable *decl, Expression *expr, StatementList &&stmts, location loc)
      : Statement(loc), decl(decl), expr(expr), stmts(std::move(stmts))
  {
  }

  Variable *decl = nullptr;
  Expression *expr = nullptr;
  StatementList stmts;

  SizedType ctx_type;

private:
  For(const For &other) = default;
};

class Config : public Statement {
public:
  DEFINE_ACCEPT

  Config(StatementList &&stmts) : stmts(std::move(stmts))
  {
  }

  StatementList stmts;

private:
  Config(const Config &other) = default;
};

class Scope : public Node {
public:
  Scope(StatementList &&stmts);
  virtual ~Scope() = default;

  StatementList stmts;
};

class AttachPoint : public Node {
public:
  DEFINE_ACCEPT

  explicit AttachPoint(const std::string &raw_input, location loc = location());
  AttachPoint(const std::string &raw_input, bool ignore_invalid)
      : AttachPoint(raw_input)
  {
    this->ignore_invalid = ignore_invalid;
  }

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

  AttachPoint create_expansion_copy(const std::string &match) const;

  int index() const;
  void set_index(int index);

private:
  AttachPoint(const AttachPoint &other) = default;

  int index_ = 0;
};
using AttachPointList = std::vector<AttachPoint *>;

class Probe : public Scope {
public:
  DEFINE_ACCEPT

  Probe(AttachPointList &&attach_points,
        Predicate *pred,
        StatementList &&stmts);

  AttachPointList attach_points;
  Predicate *pred = nullptr;

  std::string name() const;
  std::string args_typename() const;
  bool need_expansion = false;    // must build a BPF program per wildcard match
  int tp_args_structs_level = -1; // number of levels of structs that must
                                  // be imported/resolved for tracepoints

  int index() const;
  void set_index(int index);

  bool has_ap_of_probetype(ProbeType probe_type);

private:
  Probe(const Probe &other) = default;
  int index_ = 0;
};
using ProbeList = std::vector<Probe *>;

class SubprogArg : public Node {
public:
  DEFINE_ACCEPT

  SubprogArg(std::string name, SizedType type);

  std::string name() const;
  SizedType type;

private:
  SubprogArg(const SubprogArg &other) = default;
  std::string name_;
};
using SubprogArgList = std::vector<SubprogArg *>;

class Subprog : public Scope {
public:
  DEFINE_ACCEPT

  Subprog(std::string name,
          SizedType return_type,
          SubprogArgList &&args,
          StatementList &&stmts);

  SubprogArgList args;
  SizedType return_type;

  std::string name() const;

private:
  Subprog(const Subprog &other) = default;
  std::string name_;
};
using SubprogList = std::vector<Subprog *>;

class Program : public Node {
public:
  DEFINE_ACCEPT

  Program(const std::string &c_definitions,
          Config *config,
          SubprogList &&functions,
          ProbeList &&probes);

  std::string c_definitions;
  Config *config = nullptr;
  SubprogList functions;
  ProbeList probes;

private:
  Program(const Program &other) = default;
};

std::string opstr(const Binop &binop);
std::string opstr(const Unop &unop);
std::string opstr(const Jump &jump);

SizedType ident_to_record(const std::string &ident, int pointer_level = 0);

template <typename T>
concept NodeType = std::derived_from<T, Node>;

/*
 * Manages the lifetime of AST nodes.
 *
 * Nodes allocated by an ASTContext will be kept alive for the duration of the
 * owning ASTContext object.
 */
class ASTContext {
public:
  Program *root = nullptr;

  /*
   * Creates and returns a pointer to an AST node.
   */
  template <NodeType T, typename... Args>
  T *make_node(Args &&...args)
  {
    auto uniq_ptr = std::make_unique<T>(std::forward<Args>(args)...);
    auto *raw_ptr = uniq_ptr.get();
    nodes_.push_back(std::move(uniq_ptr));
    return raw_ptr;
  }

private:
  std::vector<std::unique_ptr<Node>> nodes_;
};

#undef DEFINE_ACCEPT

} // namespace ast
} // namespace bpftrace
