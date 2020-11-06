#pragma once

#include "location.hh"
#include "utils.h"
#include <map>
#include <string>
#include <vector>

#include "types.h"
#include "usdt.h"

namespace bpftrace {
namespace ast {

class Visitor;

#define DEFINE_ACCEPT void accept(Visitor &v) override;

class Node {
public:
  Node();
  Node(location loc);
  virtual ~Node() = default;
  virtual void accept(Visitor &v) = 0;
  location loc;
};

class Map;
class Variable;
class Expression : public Node {
public:
  Expression(location loc);
  SizedType type;
  Map *key_for_map = nullptr;
  Map *map = nullptr; // Only set when this expression is assigned to a map
  Variable *var = nullptr; // Set when this expression is assigned to a variable
  bool is_literal = false;
  bool is_variable = false;
  bool is_map = false;
};
using ExpressionList = std::vector<Expression *>;

class Integer : public Expression {
public:
  explicit Integer(long n, location loc);
  long n;

  DEFINE_ACCEPT
};

class PositionalParameter : public Expression {
public:
  explicit PositionalParameter(PositionalParameterType ptype,
                               long n,
                               location loc);
  PositionalParameterType ptype;
  long n;
  bool is_in_str = false;

  DEFINE_ACCEPT
};

class String : public Expression {
public:
  explicit String(const std::string &str, location loc);
  std::string str;

  DEFINE_ACCEPT
};

class StackMode : public Expression {
public:
  explicit StackMode(const std::string &mode, location loc);
  std::string mode;

  DEFINE_ACCEPT
};

class Identifier : public Expression {
public:
  explicit Identifier(const std::string &ident, location loc);
  std::string ident;

  DEFINE_ACCEPT
};

class Builtin : public Expression {
public:
  explicit Builtin(const std::string &ident, location loc);
  std::string ident;
  int probe_id;

  DEFINE_ACCEPT
};

class Call : public Expression {
public:
  explicit Call(const std::string &func, location loc);
  Call(const std::string &func, ExpressionList *vargs, location loc);
  std::string func;
  ExpressionList *vargs;

  DEFINE_ACCEPT
};

class Map : public Expression {
public:
  explicit Map(const std::string &ident, location loc);
  Map(const std::string &ident, ExpressionList *vargs, location loc);
  std::string ident;
  ExpressionList *vargs;
  bool skip_key_validation = false;

  DEFINE_ACCEPT
};

class Variable : public Expression {
public:
  explicit Variable(const std::string &ident, location loc);
  std::string ident;

  DEFINE_ACCEPT
};

class Binop : public Expression {
public:
  Binop(Expression *left, int op, Expression *right, location loc);
  Expression *left, *right;
  int op;

  DEFINE_ACCEPT
};

class Unop : public Expression {
public:
  Unop(int op, Expression *expr, location loc = location());
  Unop(int op,
       Expression *expr,
       bool is_post_op = false,
       location loc = location());
  Expression *expr;
  int op;
  bool is_post_op;

  DEFINE_ACCEPT
};

class FieldAccess : public Expression {
public:
  FieldAccess(Expression *expr, const std::string &field);
  FieldAccess(Expression *expr, const std::string &field, location loc);
  FieldAccess(Expression *expr, ssize_t index, location loc);
  Expression *expr;
  std::string field;
  ssize_t index = -1;

  DEFINE_ACCEPT
};

class ArrayAccess : public Expression {
public:
  ArrayAccess(Expression *expr, Expression *indexpr);
  ArrayAccess(Expression *expr, Expression *indexpr, location loc);
  Expression *expr;
  Expression *indexpr;

  DEFINE_ACCEPT
};

class Cast : public Expression {
public:
  Cast(const std::string &type,
       bool is_pointer,
       bool is_double_pointer,
       Expression *expr);
  Cast(const std::string &type,
       bool is_pointer,
       bool is_double_pointer,
       Expression *expr,
       location loc);
  std::string cast_type;
  bool is_pointer;
  bool is_double_pointer;
  Expression *expr;

  DEFINE_ACCEPT
};

class Tuple : public Expression
{
public:
  Tuple(ExpressionList *elems, location loc);
  ExpressionList *elems;

  DEFINE_ACCEPT
};

class Statement : public Node {
public:
  Statement() = default;
  Statement(location loc);
};
using StatementList = std::vector<Statement *>;

class ExprStatement : public Statement {
public:
  explicit ExprStatement(Expression *expr, location loc);
  Expression *expr;

  DEFINE_ACCEPT
};

class AssignMapStatement : public Statement {
public:
  AssignMapStatement(Map *map, Expression *expr, location loc = location());
  Map *map;
  Expression *expr;

  DEFINE_ACCEPT
};

class AssignVarStatement : public Statement {
public:
  AssignVarStatement(Variable *var, Expression *expr);
  AssignVarStatement(Variable *var, Expression *expr, location loc);
  Variable *var;
  Expression *expr;

  DEFINE_ACCEPT
};

class If : public Statement {
public:
  If(Expression *cond, StatementList *stmts);
  If(Expression *cond, StatementList *stmts, StatementList *else_stmts);
  Expression *cond;
  StatementList *stmts = nullptr;
  StatementList *else_stmts = nullptr;

  DEFINE_ACCEPT
};

class Unroll : public Statement {
public:
  Unroll(Expression *expr, StatementList *stmts, location loc);
  long int var = 0;
  Expression *expr;
  StatementList *stmts;

  DEFINE_ACCEPT
};

class Jump : public Statement
{
public:
  Jump(int ident, location loc = location()) : loc(loc), ident(ident)
  {
  }

  location loc;
  int ident;

  DEFINE_ACCEPT
};

class Predicate : public Node {
public:
  explicit Predicate(Expression *expr, location loc);
  Expression *expr;

  DEFINE_ACCEPT
};

class Ternary : public Expression {
public:
  Ternary(Expression *cond, Expression *left, Expression *right);
  Ternary(Expression *cond, Expression *left, Expression *right, location loc);
  Expression *cond, *left, *right;

  DEFINE_ACCEPT
};

class While : public Statement
{
public:
  While(Expression *cond, StatementList *stmts, location loc)
      : cond(cond), stmts(stmts), loc(loc)
  {
  }
  Expression *cond;
  StatementList *stmts = nullptr;
  location loc;

  DEFINE_ACCEPT
};

class AttachPoint : public Node {
public:
  explicit AttachPoint(const std::string &raw_input, location loc = location());

  // Raw, unparsed input from user, eg. kprobe:vfs_read
  std::string raw_input;

  std::string provider;
  std::string target;
  std::string ns;
  std::string func;
  usdt_probe_entry usdt; // resolved USDT entry, used to support arguments with wildcard matches
  int freq = 0;
  uint64_t len = 0; // for watchpoint probes, the width of watched addr
  std::string mode; // for watchpoint probes, the watch mode
  bool need_expansion = false;
  uint64_t address = 0;
  uint64_t func_offset = 0;

  DEFINE_ACCEPT
  std::string name(const std::string &attach_point) const;
  std::string name(const std::string &attach_target,
                   const std::string &attach_point) const;

  int index(std::string name);
  void set_index(std::string name, int index);
private:
  std::map<std::string, int> index_;
};
using AttachPointList = std::vector<AttachPoint *>;

class Probe : public Node {
public:
  Probe(AttachPointList *attach_points, Predicate *pred, StatementList *stmts);

  AttachPointList *attach_points;
  Predicate *pred;
  StatementList *stmts;

  DEFINE_ACCEPT
  std::string name() const;
  bool need_expansion = false;        // must build a BPF program per wildcard match
  bool need_tp_args_structs = false;  // must import struct for tracepoints

  int index();
  void set_index(int index);
private:
  int index_ = 0;
};
using ProbeList = std::vector<Probe *>;

class Program : public Node {
public:
  Program(const std::string &c_definitions, ProbeList *probes);
  std::string c_definitions;
  ProbeList *probes;

  DEFINE_ACCEPT
};

std::string opstr(Binop &binop);
std::string opstr(Unop &unop);
std::string opstr(Jump &jump);

#undef DEFINE_ACCEPT

} // namespace ast
} // namespace bpftrace
