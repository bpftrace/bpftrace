#pragma once

#include "location.hh"
#include "utils.h"
#include <map>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdlib>
#include <memory>
#include <optional>
#include <functional>

#include "types.h"
#include "imap.h"
#include "ring_indexer.h"

namespace bpftrace {
namespace ast {

class Visitor;

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
  Expression();
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
  explicit Integer(long n);
  explicit Integer(long n, location loc);
  long n;

  void accept(Visitor &v) override;
};

class PositionalParameter : public Expression {
public:
  explicit PositionalParameter(PositionalParameterType ptype, long n);
  explicit PositionalParameter(PositionalParameterType ptype,
                               long n,
                               location loc);
  PositionalParameterType ptype;
  long n;
  bool is_in_str = false;

  void accept(Visitor &v) override;
};

class String : public Expression {
public:
  explicit String(const std::string &str);
  explicit String(const std::string &str, location loc);
  std::string str;

  void accept(Visitor &v) override;
};

class StackMode : public Expression {
public:
  explicit StackMode(const std::string &mode);
  explicit StackMode(const std::string &mode, location loc);
  std::string mode;

  void accept(Visitor &v) override;
};

class Identifier : public Expression {
public:
  explicit Identifier(const std::string &ident);
  explicit Identifier(const std::string &ident, location loc);
  std::string ident;

  void accept(Visitor &v) override;
};

class Builtin : public Expression {
public:
  explicit Builtin(const std::string &ident);
  explicit Builtin(const std::string &ident, location loc);
  std::string ident;
  int probe_id;

  void accept(Visitor &v) override;
};

class Call : public Expression {
public:
  Call(const std::string &func, location loc, ExpressionList *vargs = nullptr);
  std::string func;
  ExpressionList *vargs;

  void accept(Visitor &v) override;
};

class StrCall : public Call {
public:
  class StrMapState {
    public:
    struct ZeroesDeleter {
      void operator()(std::byte* bytes);
    };
    StrMapState(
      std::unique_ptr<IMap> map,
      RingIndexer ringIndexer,
      std::unique_ptr<std::byte, ZeroesDeleter> zeroesForClearingMap
      );
    std::unique_ptr<IMap> map;
    RingIndexer ringIndexer;
    std::unique_ptr<std::byte, ZeroesDeleter> zeroesForClearingMap;
  };
  StrCall(location loc, ExpressionList *vargs = nullptr);
  std::optional<StrMapState> state;
  std::optional<int> maxStrSize;
};

class CallFactory {
  public:
  static Call* createCall(const std::string &func, location loc, ExpressionList *vargs = nullptr);
};

class Map : public Expression {
public:
  explicit Map(const std::string &ident, location loc);
  Map(const std::string &ident, ExpressionList *vargs);
  Map(const std::string &ident, ExpressionList *vargs, location loc);
  std::string ident;
  ExpressionList *vargs;
  bool skip_key_validation = false;

  void accept(Visitor &v) override;
};

class Variable : public Expression {
public:
  explicit Variable(const std::string &ident);
  explicit Variable(const std::string &ident, location loc);
  std::string ident;

  void accept(Visitor &v) override;
};

class Binop : public Expression {
public:
  Binop(Expression *left, int op, Expression *right, location loc);
  Expression *left, *right;
  int op;

  void accept(Visitor &v) override;
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

  void accept(Visitor &v) override;
};

class FieldAccess : public Expression {
public:
  FieldAccess(Expression *expr, const std::string &field);
  FieldAccess(Expression *expr, const std::string &field, location loc);
  Expression *expr;
  std::string field;

  void accept(Visitor &v) override;
};

class ArrayAccess : public Expression {
public:
  ArrayAccess(Expression *expr, Expression *indexpr);
  ArrayAccess(Expression *expr, Expression *indexpr, location loc);
  Expression *expr;
  Expression *indexpr;

  void accept(Visitor &v) override;
};

class Cast : public Expression {
public:
  Cast(const std::string &type, bool is_pointer, Expression *expr);
  Cast(const std::string &type,
       bool is_pointer,
       Expression *expr,
       location loc);
  std::string cast_type;
  bool is_pointer;
  Expression *expr;

  void accept(Visitor &v) override;
};

class Statement : public Node {
public:
  Statement() = default;
  Statement(location loc);
};
using StatementList = std::vector<Statement *>;

class ExprStatement : public Statement {
public:
  explicit ExprStatement(Expression *expr);
  explicit ExprStatement(Expression *expr, location loc);
  Expression *expr;

  void accept(Visitor &v) override;
};

class AssignMapStatement : public Statement {
public:
  AssignMapStatement(Map *map, Expression *expr, location loc = location());
  Map *map;
  Expression *expr;

  void accept(Visitor &v) override;
};

class AssignVarStatement : public Statement {
public:
  AssignVarStatement(Variable *var, Expression *expr);
  AssignVarStatement(Variable *var, Expression *expr, location loc);
  Variable *var;
  Expression *expr;

  void accept(Visitor &v) override;
};

class If : public Statement {
public:
  If(Expression *cond, StatementList *stmts);
  If(Expression *cond, StatementList *stmts, StatementList *else_stmts);
  Expression *cond;
  StatementList *stmts = nullptr;
  StatementList *else_stmts = nullptr;

  void accept(Visitor &v) override;
};

class Unroll : public Statement {
public:
  Unroll(Expression *expr, StatementList *stmts, location loc);
  long int var = 0;
  Expression *expr;
  StatementList *stmts;

  void accept(Visitor &v) override;
};

class Jump : public Statement
{
public:
  Jump(int ident, location loc = location()) : loc(loc), ident(ident)
  {
  }

  location loc;
  int ident;

  void accept(Visitor &v) override;
};

class Predicate : public Node {
public:
  explicit Predicate(Expression *expr);
  explicit Predicate(Expression *expr, location loc);
  Expression *expr;

  void accept(Visitor &v) override;
};

class Ternary : public Expression {
public:
  Ternary(Expression *cond, Expression *left, Expression *right);
  Ternary(Expression *cond, Expression *left, Expression *right, location loc);
  Expression *cond, *left, *right;

  void accept(Visitor &v) override;
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

  void accept(Visitor &v) override;
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

  void accept(Visitor &v) override;
  std::string name(const std::string &attach_point) const;

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

  void accept(Visitor &v) override;
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

  void accept(Visitor &v) override;
};

class Visitor {
public:
  virtual ~Visitor() = default;
  virtual void visit(Integer &integer) = 0;
  virtual void visit(PositionalParameter &integer) = 0;
  virtual void visit(String &string) = 0;
  virtual void visit(Builtin &builtin) = 0;
  virtual void visit(Identifier &identifier) = 0;
  virtual void visit(StackMode &mode) = 0;
  virtual void visit(Call &call) = 0;
  virtual void visit(Map &map) = 0;
  virtual void visit(Variable &var) = 0;
  virtual void visit(Binop &binop) = 0;
  virtual void visit(Unop &unop) = 0;
  virtual void visit(Ternary &ternary) = 0;
  virtual void visit(FieldAccess &acc) = 0;
  virtual void visit(ArrayAccess &arr) = 0;
  virtual void visit(Cast &cast) = 0;
  virtual void visit(ExprStatement &expr) = 0;
  virtual void visit(AssignMapStatement &assignment) = 0;
  virtual void visit(AssignVarStatement &assignment) = 0;
  virtual void visit(If &if_block) = 0;
  virtual void visit(Jump &jump) = 0;
  virtual void visit(Unroll &unroll) = 0;
  virtual void visit(While &while_block) = 0;
  virtual void visit(Predicate &pred) = 0;
  virtual void visit(AttachPoint &ap) = 0;
  virtual void visit(Probe &probe) = 0;
  virtual void visit(Program &program) = 0;
};

std::string opstr(Binop &binop);
std::string opstr(Unop &unop);
std::string opstr(Jump &jump);

} // namespace ast
} // namespace bpftrace
