#pragma once

#include <cstdint>
#include <string>
#include <variant>
#include <vector>

#include "diagnostic.h"
#include "types.h"
#include "usdt.h"

namespace bpftrace::ast {

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
// - session expansion - extension of the multi expansion when a single BPF
//                       program is shared for both the entry and the exit probe
//                       (when they are both attached to the same attach points)
//                       using the kprobe.session mechanism
enum class ExpansionType {
  NONE,
  FULL,
  MULTI,
  SESSION,
};

class Node {
public:
  Node(ASTContext &ctx, Location &&loc) : ctx_(ctx), loc(loc) {};
  virtual ~Node() = default;

  Node(const Node &) = delete;
  Node &operator=(const Node &) = delete;
  Node(Node &&) = delete;
  Node &operator=(Node &&) = delete;

  Diagnostic &addError() const;
  Diagnostic &addWarning() const;

private:
  ASTContext &ctx_;

public:
  // This is temporarily accessible by other classes because we don't have a
  // clear `clone` operation at this time. Eventually this should be made
  // private and we should rely on a clear model for cloning nodes.
  Location loc;
};

class Map;
class Variable;
class Expression : public Node {
public:
  Expression(ASTContext &ctx, Location &&loc) : Node(ctx, std::move(loc)) {};
  ~Expression() override = default;

  SizedType type;
  Map *key_for_map = nullptr;
  Map *map = nullptr;      // Only set when this expression is assigned to a map
  Variable *var = nullptr; // Set when this expression is assigned to a variable
  bool is_literal = false;
};
using ExpressionList = std::vector<Expression *>;

class Integer : public Expression {
public:
  explicit Integer(ASTContext &ctx,
                   int64_t n,
                   Location &&loc,
                   bool is_negative = true);

  int64_t n;
  bool is_negative;
};

class PositionalParameter : public Expression {
public:
  explicit PositionalParameter(ASTContext &ctx, long n, Location &&loc);

  long n;
  bool is_in_str = false;
};

class PositionalParameterCount : public Expression {
public:
  explicit PositionalParameterCount(ASTContext &ctx, Location &&loc);
};

class String : public Expression {
public:
  explicit String(ASTContext &ctx, std::string str, Location &&loc);

  std::string str;
};

class Identifier : public Expression {
public:
  explicit Identifier(ASTContext &ctx, std::string ident, Location &&loc);

  std::string ident;
};

class Builtin : public Expression {
public:
  explicit Builtin(ASTContext &ctx, std::string ident, Location &&loc);

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
  explicit Call(ASTContext &ctx, std::string func, Location &&loc);
  Call(ASTContext &ctx,
       std::string func,
       ExpressionList &&vargs,
       Location &&loc);

  std::string func;
  ExpressionList vargs;
};

class Sizeof : public Expression {
public:
  Sizeof(ASTContext &ctx, SizedType type, Location &&loc);
  Sizeof(ASTContext &ctx, Expression *expr, Location &&loc);

  Expression *expr = nullptr;
  SizedType argtype;
};

class Offsetof : public Expression {
public:
  Offsetof(ASTContext &ctx,
           SizedType record,
           std::vector<std::string> &field,
           Location &&loc);
  Offsetof(ASTContext &ctx,
           Expression *expr,
           std::vector<std::string> &field,
           Location &&loc);

  SizedType record;
  Expression *expr = nullptr;
  std::vector<std::string> field;
};

class MapDeclStatement : public Node {
public:
  explicit MapDeclStatement(ASTContext &ctx,
                            std::string ident,
                            std::string bpf_type,
                            int max_entries,
                            Location &&loc);
  std::string ident;
  std::string bpf_type;
  int max_entries;
};

class Map : public Expression {
public:
  explicit Map(ASTContext &ctx,
               std::string ident,
               Expression *expr,
               Location &&loc);

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
  explicit Variable(ASTContext &ctx, std::string ident, Location &&loc);

  std::string ident;
};

class Binop : public Expression {
public:
  Binop(ASTContext &ctx,
        Expression *left,
        Operator op,
        Expression *right,
        Location &&loc);

  Expression *left = nullptr;
  Expression *right = nullptr;
  Operator op;
};

class Unop : public Expression {
public:
  Unop(ASTContext &ctx,
       Operator op,
       Expression *expr,
       bool is_post_op,
       Location &&loc);

  Expression *expr = nullptr;
  Operator op;
  bool is_post_op;
};

class FieldAccess : public Expression {
public:
  FieldAccess(ASTContext &ctx,
              Expression *expr,
              std::string field,
              Location &&loc);

  Expression *expr = nullptr;
  std::string field;
};

class ArrayAccess : public Expression {
public:
  ArrayAccess(ASTContext &ctx,
              Expression *expr,
              Expression *indexpr,
              Location &&loc);

  Expression *expr = nullptr;
  Expression *indexpr = nullptr;
};

class TupleAccess : public Expression {
public:
  TupleAccess(ASTContext &ctx, Expression *expr, ssize_t index, Location &&loc);

  Expression *expr = nullptr;
  ssize_t index;
};

class Cast : public Expression {
public:
  Cast(ASTContext &ctx, SizedType type, Expression *expr, Location &&loc);

  Expression *expr = nullptr;
};

class Tuple : public Expression {
public:
  Tuple(ASTContext &ctx, ExpressionList &&elems, Location &&loc);

  ExpressionList elems;
};

class Statement : public Node {
public:
  Statement(ASTContext &ctx, Location &&loc) : Node(ctx, std::move(loc)) {};
};

using StatementList = std::vector<Statement *>;

class ExprStatement : public Statement {
public:
  explicit ExprStatement(ASTContext &ctx, Expression *expr, Location &&loc);

  Expression *expr = nullptr;
};

using MapDeclList = std::vector<MapDeclStatement *>;

class VarDeclStatement : public Statement {
public:
  VarDeclStatement(ASTContext &ctx,
                   Variable *var,
                   SizedType type,
                   Location &&loc);
  VarDeclStatement(ASTContext &ctx, Variable *var, Location &&loc);

  Variable *var = nullptr;
  bool set_type = false;
};

class AssignMapStatement : public Statement {
public:
  AssignMapStatement(ASTContext &ctx,
                     Map *map,
                     Expression *expr,
                     Location &&loc);

  Map *map = nullptr;
  Expression *expr = nullptr;
};

class AssignVarStatement : public Statement {
public:
  AssignVarStatement(ASTContext &ctx,
                     Variable *var,
                     Expression *expr,
                     Location &&loc);
  AssignVarStatement(ASTContext &ctx,
                     VarDeclStatement *var_decl_stmt,
                     Expression *expr,
                     Location &&loc);

  VarDeclStatement *var_decl_stmt = nullptr;
  Variable *var = nullptr;
  Expression *expr = nullptr;
};

class AssignConfigVarStatement : public Node {
public:
  AssignConfigVarStatement(ASTContext &ctx,
                           std::string var,
                           uint64_t value,
                           Location &&loc);
  AssignConfigVarStatement(ASTContext &ctx,
                           std::string var,
                           std::string value,
                           Location &&loc);

  std::string var;
  std::variant<uint64_t, std::string> value;
};
using ConfigStatementList = std::vector<AssignConfigVarStatement *>;

class Block : public Expression {
public:
  Block(ASTContext &ctx, StatementList &&stmts, Location &&loc);
  Block(ASTContext &ctx,
        StatementList &&stmts,
        Expression *expr,
        Location &&loc);

  StatementList stmts;
  // Depending on how it is parsed, a block can also be evaluated as an
  // expression. This follows all other statements in the block.
  Expression *expr = nullptr;
};

class If : public Statement {
public:
  If(ASTContext &ctx,
     Expression *cond,
     Block *if_block,
     Block *else_block,
     Location &&loc);

  Expression *cond = nullptr;
  Block *if_block = nullptr;
  Block *else_block = nullptr;
};

class Unroll : public Statement {
public:
  Unroll(ASTContext &ctx, Expression *expr, Block *block, Location &&loc);

  long int var = 0;
  Expression *expr = nullptr;
  Block *block = nullptr;
};

class Jump : public Statement {
public:
  Jump(ASTContext &ctx,
       JumpType ident,
       Expression *return_value,
       Location &&loc)
      : Statement(ctx, std::move(loc)), ident(ident), return_value(return_value)
  {
  }
  Jump(ASTContext &ctx, JumpType ident, Location &&loc)
      : Statement(ctx, std::move(loc)), ident(ident), return_value(nullptr)
  {
  }

  JumpType ident = JumpType::INVALID;
  Expression *return_value;
};

class Predicate : public Node {
public:
  explicit Predicate(ASTContext &ctx, Expression *expr, Location &&loc);

  Expression *expr = nullptr;
};

class Ternary : public Expression {
public:
  Ternary(ASTContext &ctx,
          Expression *cond,
          Expression *left,
          Expression *right,
          Location &&loc);

  Expression *cond = nullptr;
  Expression *left = nullptr;
  Expression *right = nullptr;
};

class While : public Statement {
public:
  While(ASTContext &ctx, Expression *cond, Block *block, Location &&loc)
      : Statement(ctx, std::move(loc)), cond(cond), block(block)
  {
  }

  Expression *cond = nullptr;
  Block *block = nullptr;
};

class For : public Statement {
public:
  For(ASTContext &ctx,
      Variable *decl,
      Map *map,
      StatementList &&stmts,
      Location &&loc)
      : Statement(ctx, std::move(loc)),
        decl(decl),
        map(map),
        stmts(std::move(stmts))
  {
  }

  Variable *decl = nullptr;
  Map *map = nullptr;
  StatementList stmts;
  SizedType ctx_type;
};

class Config : public Node {
public:
  Config(ASTContext &ctx, ConfigStatementList &&stmts, Location &&loc)
      : Node(ctx, std::move(loc)), stmts(std::move(stmts))
  {
  }

  ConfigStatementList stmts;
};

class Probe;
class AttachPoint : public Node {
public:
  AttachPoint(ASTContext &ctx,
              std::string raw_input,
              bool ignore_invalid,
              Location &&loc);

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
  Probe *ret_probe = nullptr; // for session probes

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
  Probe(ASTContext &ctx,
        AttachPointList &&attach_points,
        Predicate *pred,
        Block *block,
        Location &&loc);

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
  SubprogArg(ASTContext &ctx, std::string name, SizedType type, Location &&loc);

  std::string name() const;
  SizedType type;

private:
  std::string name_;
};
using SubprogArgList = std::vector<SubprogArg *>;

class Subprog : public Node {
public:
  Subprog(ASTContext &ctx,
          std::string name,
          SizedType return_type,
          SubprogArgList &&args,
          StatementList &&stmts,
          Location &&loc);

  SubprogArgList args;
  SizedType return_type;
  StatementList stmts;

  std::string name() const;

private:
  std::string name_;
};
using SubprogList = std::vector<Subprog *>;

class Import : public Node {
public:
  Import(ASTContext &ctx, std::string name, Location &&loc);

  const std::string &name() const
  {
    return name_;
  }

private:
  std::string name_;
};
using ImportList = std::vector<Import *>;

class Program : public Node {
public:
  Program(ASTContext &ctx,
          std::string c_definitions,
          Config *config,
          ImportList &&imports,
          MapDeclList &&map_decls,
          SubprogList &&functions,
          ProbeList &&probes,
          Location &&loc);

  std::string c_definitions;
  Config *config = nullptr;
  ImportList imports;
  SubprogList functions;
  ProbeList probes;
  MapDeclList map_decls;
};

std::string opstr(const Binop &binop);
std::string opstr(const Unop &unop);
std::string opstr(const Jump &jump);

SizedType ident_to_record(const std::string &ident, int pointer_level = 0);
SizedType ident_to_sized_type(const std::string &ident);

} // namespace bpftrace::ast
