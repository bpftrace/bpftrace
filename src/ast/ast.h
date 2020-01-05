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
  Node() = default;
  Node(location loc) : loc(loc){};
  Node(const Node &other) = default;
  virtual ~Node() = default;

  virtual void accept(Visitor &v) = 0;

  location loc;
};

class Map;
class Variable;
class Expression : public Node {
public:
  Expression() = default;
  Expression(location loc) : Node(loc){};
  Expression(const Expression &other);
  // NB: do not free any of non-owned pointers we store
  virtual ~Expression() = default;

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
  Integer(const Integer &other) = default;
  long n;

  DEFINE_ACCEPT
};

class PositionalParameter : public Expression {
public:
  explicit PositionalParameter(PositionalParameterType ptype,
                               long n,
                               location loc);
  PositionalParameter(const PositionalParameter &other) = default;

  PositionalParameterType ptype;
  long n;
  bool is_in_str = false;

  DEFINE_ACCEPT
};

class String : public Expression {
public:
  explicit String(const std::string &str, location loc);
  String(const String &other) = default;

  std::string str;

  DEFINE_ACCEPT
};

class StackMode : public Expression {
public:
  explicit StackMode(const std::string &mode, location loc);
  StackMode(const StackMode &other) = default;

  std::string mode;

  DEFINE_ACCEPT
};

class Identifier : public Expression {
public:
  explicit Identifier(const std::string &ident, location loc);
  Identifier(const Identifier &other) = default;

  std::string ident;

  DEFINE_ACCEPT
};

class Builtin : public Expression {
public:
  explicit Builtin(const std::string &ident, location loc);
  Builtin(const Builtin &other) = default;

  std::string ident;
  int probe_id;

  DEFINE_ACCEPT
};

class Call : public Expression {
public:
  explicit Call(const std::string &func, location loc);
  Call(const std::string &func, ExpressionList *vargs, location loc);
  Call(const Call &other);
  ~Call()
  {
    if (vargs)
      for (Expression *expr : *vargs)
        delete expr;

    delete vargs;
    vargs = nullptr;
  }

  std::string func;
  ExpressionList *vargs = nullptr;

  DEFINE_ACCEPT
};

class Map : public Expression {
public:
  explicit Map(const std::string &ident, location loc);
  Map(const std::string &ident, ExpressionList *vargs, location loc);
  Map(const Map &other);
  ~Map()
  {
    if (vargs)
      for (Expression *expr : *vargs)
        delete expr;

    delete vargs;
    vargs = nullptr;
  }

  std::string ident;
  ExpressionList *vargs = nullptr;
  bool skip_key_validation = false;

  DEFINE_ACCEPT
};

class Variable : public Expression {
public:
  explicit Variable(const std::string &ident, location loc);
  Variable(const Variable &other) = default;

  std::string ident;

  DEFINE_ACCEPT
};

class Binop : public Expression {
public:
  Binop(Expression *left, int op, Expression *right, location loc);
  Binop(const Binop &other);

  ~Binop()
  {
    delete left;
    delete right;
    left = nullptr;
    right = nullptr;
  }

  Expression *left = nullptr;
  Expression *right = nullptr;
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
  Unop(const Unop &other);

  ~Unop()
  {
    delete expr;
    expr = nullptr;
  }

  Expression *expr = nullptr;
  int op;
  bool is_post_op;

  DEFINE_ACCEPT
};

class FieldAccess : public Expression {
public:
  FieldAccess(Expression *expr, const std::string &field);
  FieldAccess(Expression *expr, const std::string &field, location loc);
  FieldAccess(Expression *expr, ssize_t index, location loc);
  FieldAccess(const FieldAccess &other);
  ~FieldAccess()
  {
    delete expr;
    expr = nullptr;
  }

  Expression *expr = nullptr;
  std::string field;
  ssize_t index = -1;

  DEFINE_ACCEPT
};

class ArrayAccess : public Expression {
public:
  ArrayAccess(Expression *expr, Expression *indexpr);
  ArrayAccess(Expression *expr, Expression *indexpr, location loc);
  ArrayAccess(const ArrayAccess &other) : Expression(other){};
  ~ArrayAccess()
  {
    delete expr;
    delete indexpr;
    expr = nullptr;
    indexpr = nullptr;
  }

  Expression *expr = nullptr;
  Expression *indexpr = nullptr;
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
  Cast(const Cast &other);
  ~Cast()
  {
    delete expr;
    expr = nullptr;
  }

  std::string cast_type;
  bool is_pointer;
  bool is_double_pointer;
  Expression *expr = nullptr;

  DEFINE_ACCEPT
};

class Tuple : public Expression
{
public:
  Tuple(ExpressionList *elems, location loc);
  Tuple(const Tuple &other);
  ~Tuple()
  {
    for (Expression *expr : *elems)
      delete expr;
    delete elems;
  }

  ExpressionList *elems = nullptr;

  DEFINE_ACCEPT
};

class Statement : public Node {
public:
  Statement() = default;
  Statement(location loc) : Node(loc){};
  Statement(const Statement &other) = default;
};

using StatementList = std::vector<Statement *>;

class ExprStatement : public Statement {
public:
  explicit ExprStatement(Expression *expr, location loc);
  ExprStatement(const ExprStatement &other) : Statement(other){};
  ~ExprStatement()
  {
    delete expr;
    expr = nullptr;
  }

  Expression *expr = nullptr;

  DEFINE_ACCEPT
};

class AssignMapStatement : public Statement {
public:
  AssignMapStatement(Map *map, Expression *expr, location loc = location());
  AssignMapStatement(const AssignMapStatement &other) : Statement(other){};
  ~AssignMapStatement()
  {
    delete map;
    delete expr;
    map = nullptr;
    expr = nullptr;
  }

  Map *map = nullptr;
  Expression *expr = nullptr;

  DEFINE_ACCEPT
};

class AssignVarStatement : public Statement {
public:
  AssignVarStatement(Variable *var, Expression *expr);
  AssignVarStatement(Variable *var, Expression *expr, location loc);
  AssignVarStatement(const AssignVarStatement &other) : Statement(other){};
  ~AssignVarStatement()
  {
    delete var;
    delete expr;
    var = nullptr;
    expr = nullptr;
  }

  Variable *var = nullptr;
  Expression *expr = nullptr;

  DEFINE_ACCEPT
};

class If : public Statement {
public:
  If(Expression *cond, StatementList *stmts);
  If(Expression *cond, StatementList *stmts, StatementList *else_stmts);
  If(const If &other);
  ~If()
  {
    delete cond;
    cond = nullptr;

    if (stmts)
      for (Statement *s : *stmts)
        delete s;
    delete stmts;
    stmts = nullptr;

    if (else_stmts)
      for (Statement *s : *else_stmts)
        delete s;
    delete else_stmts;
    else_stmts = nullptr;
  }

  Expression *cond = nullptr;
  StatementList *stmts = nullptr;
  StatementList *else_stmts = nullptr;

  DEFINE_ACCEPT
};

class Unroll : public Statement {
public:
  Unroll(Expression *expr, StatementList *stmts, location loc);
  Unroll(const Unroll &other);
  ~Unroll()
  {
    if (stmts)
      for (Statement *s : *stmts)
        delete s;
    delete stmts;
    stmts = nullptr;
  }

  long int var = 0;
  Expression *expr = nullptr;
  StatementList *stmts = nullptr;

  DEFINE_ACCEPT
};

class Jump : public Statement
{
public:
  Jump(int ident, location loc = location()) : Statement(loc), ident(ident)
  {
  }
  Jump(const Jump &other) = default;
  ~Jump() = default;

  int ident = 0;

  DEFINE_ACCEPT
};

class Predicate : public Node {
public:
  explicit Predicate(Expression *expr, location loc);
  Predicate(const Predicate &other) : Node(other){};
  ~Predicate()
  {
    delete expr;
    expr = nullptr;
  }

  Expression *expr = nullptr;

  DEFINE_ACCEPT
};

class Ternary : public Expression {
public:
  Ternary(Expression *cond, Expression *left, Expression *right, location loc);
  Ternary(const Ternary &other) : Expression(other){};
  ~Ternary()
  {
    delete cond;
    delete left;
    delete right;
    cond = nullptr;
    left = nullptr;
    right = nullptr;
  }

  Expression *cond = nullptr;
  Expression *left = nullptr;
  Expression *right = nullptr;

  DEFINE_ACCEPT
};

class While : public Statement
{
public:
  While(Expression *cond, StatementList *stmts, location loc)
      : Statement(loc), cond(cond), stmts(stmts)
  {
  }
  While(const While &other);
  ~While()
  {
    delete cond;
    for (auto *stmt : *stmts)
      delete stmt;
    delete stmts;
  }

  Expression *cond = nullptr;
  StatementList *stmts = nullptr;

  DEFINE_ACCEPT
};

class AttachPoint : public Node {
public:
  explicit AttachPoint(const std::string &raw_input, location loc = location());
  AttachPoint(const AttachPoint &other) = default;
  ~AttachPoint() = default;

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
  Probe(const Probe &other);
  ~Probe()
  {
    if (attach_points)
      for (AttachPoint *ap : *attach_points)
        delete ap;
    delete attach_points;
    attach_points = nullptr;

    delete pred;
    pred = nullptr;

    if (stmts)
      for (Statement *s : *stmts)
        delete s;
    delete stmts;
    stmts = nullptr;
  }

  AttachPointList *attach_points = nullptr;
  Predicate *pred = nullptr;
  StatementList *stmts = nullptr;

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
  Program(const Program &other);

  ~Program()
  {
    if (probes)
      for (Probe *p : *probes)
        delete p;
    delete probes;
    probes = nullptr;
  }

  std::string c_definitions;
  ProbeList *probes = nullptr;

  DEFINE_ACCEPT
};

std::string opstr(Binop &binop);
std::string opstr(Unop &unop);
std::string opstr(Jump &jump);

#undef DEFINE_ACCEPT

} // namespace ast
} // namespace bpftrace
