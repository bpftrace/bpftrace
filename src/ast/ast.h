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
using ExpressionList = std::vector<std::unique_ptr<Expression>>;

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
  explicit Call(const std::string &func);
  explicit Call(const std::string &func, location loc);
  Call(const std::string &func, std::unique_ptr<ExpressionList> vargs);
  Call(const std::string &func,
       std::unique_ptr<ExpressionList> vargs,
       location loc);
  std::string func;
  std::unique_ptr<ExpressionList> vargs;

  void accept(Visitor &v) override;
};

class Map : public Expression {
public:
  explicit Map(const std::string &ident, location loc);
  Map(const std::string &ident, std::unique_ptr<ExpressionList> vargs);
  Map(const std::string &ident,
      std::unique_ptr<ExpressionList> vargs,
      location loc);
  explicit Map(const Map &m);
  std::string ident;
  std::unique_ptr<ExpressionList> vargs;
  bool skip_key_validation = false;

  void accept(Visitor &v) override;
};

class Variable : public Expression {
public:
  explicit Variable(const std::string &ident);
  explicit Variable(const std::string &ident, location loc);
  explicit Variable(const Variable &var);
  std::string ident;

  void accept(Visitor &v) override;
};

class Binop : public Expression {
public:
  Binop(std::unique_ptr<Expression> left,
        int op,
        std::unique_ptr<Expression> right,
        location loc);
  std::unique_ptr<Expression> left, right;
  int op;

  void accept(Visitor &v) override;
};

class Unop : public Expression {
public:
  Unop(int op, std::unique_ptr<Expression> expr, location loc = location());
  Unop(int op,
       std::unique_ptr<Expression> expr,
       bool is_post_op = false,
       location loc = location());
  std::unique_ptr<Expression> expr;
  int op;
  bool is_post_op;

  void accept(Visitor &v) override;
};

class FieldAccess : public Expression {
public:
  FieldAccess(std::unique_ptr<Expression> expr, const std::string &field);
  FieldAccess(std::unique_ptr<Expression> expr,
              const std::string &field,
              location loc);
  FieldAccess(std::unique_ptr<Expression> expr, ssize_t index, location loc);
  std::unique_ptr<Expression> expr;
  std::string field;
  ssize_t index = -1;

  void accept(Visitor &v) override;
};

class ArrayAccess : public Expression {
public:
  ArrayAccess(std::unique_ptr<Expression> expr,
              std::unique_ptr<Expression> indexpr);
  ArrayAccess(std::unique_ptr<Expression> expr,
              std::unique_ptr<Expression> indexpr,
              location loc);
  std::unique_ptr<Expression> expr;
  std::unique_ptr<Expression> indexpr;

  void accept(Visitor &v) override;
};

class Cast : public Expression {
public:
  Cast(const std::string &type,
       bool is_pointer,
       std::unique_ptr<Expression> expr);
  Cast(const std::string &type,
       bool is_pointer,
       std::unique_ptr<Expression> expr,
       location loc);
  std::string cast_type;
  bool is_pointer;
  std::unique_ptr<Expression> expr;

  void accept(Visitor &v) override;
};

class Tuple : public Expression
{
public:
  Tuple(std::unique_ptr<ExpressionList> elems, location loc);
  std::unique_ptr<ExpressionList> elems;

  void accept(Visitor &v) override;
};

class Statement : public Node {
public:
  Statement() = default;
  Statement(location loc);
};
using StatementList = std::vector<std::unique_ptr<Statement>>;

class ExprStatement : public Statement {
public:
  explicit ExprStatement(std::unique_ptr<Expression> expr);
  explicit ExprStatement(std::unique_ptr<Expression> expr, location loc);
  std::unique_ptr<Expression> expr;

  void accept(Visitor &v) override;
};

class AssignMapStatement : public Statement {
public:
  AssignMapStatement(std::unique_ptr<Map> map,
                     std::unique_ptr<Expression> expr,
                     location loc = location());
  std::unique_ptr<Map> map;
  std::unique_ptr<Expression> expr;

  void accept(Visitor &v) override;
};

class AssignVarStatement : public Statement {
public:
  AssignVarStatement(std::unique_ptr<Variable> var,
                     std::unique_ptr<Expression> expr);
  AssignVarStatement(std::unique_ptr<Variable> var,
                     std::unique_ptr<Expression> expr,
                     location loc);
  std::unique_ptr<Variable> var;
  std::unique_ptr<Expression> expr;

  void accept(Visitor &v) override;
};

class If : public Statement {
public:
  If(std::unique_ptr<Expression> cond, std::unique_ptr<StatementList> stmts);
  If(std::unique_ptr<Expression> cond,
     std::unique_ptr<StatementList> stmts,
     std::unique_ptr<StatementList> else_stmts);
  std::unique_ptr<Expression> cond;
  std::unique_ptr<StatementList> stmts = nullptr;
  std::unique_ptr<StatementList> else_stmts = nullptr;

  void accept(Visitor &v) override;
};

class Unroll : public Statement {
public:
  Unroll(std::unique_ptr<Expression> expr,
         std::unique_ptr<StatementList> stmts,
         location loc);
  long int var = 0;
  std::unique_ptr<Expression> expr;
  std::unique_ptr<StatementList> stmts;

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
  explicit Predicate(std::unique_ptr<Expression> expr);
  explicit Predicate(std::unique_ptr<Expression> expr, location loc);
  std::unique_ptr<Expression> expr;

  void accept(Visitor &v) override;
};

class Ternary : public Expression {
public:
  Ternary(std::unique_ptr<Expression> cond,
          std::unique_ptr<Expression> left,
          std::unique_ptr<Expression> right);
  Ternary(std::unique_ptr<Expression> cond,
          std::unique_ptr<Expression> left,
          std::unique_ptr<Expression> right,
          location loc);
  std::unique_ptr<Expression> cond, left, right;

  void accept(Visitor &v) override;
};

class While : public Statement
{
public:
  While(std::unique_ptr<Expression> cond,
        std::unique_ptr<StatementList> stmts,
        location loc)
      : cond(std::move(cond)), stmts(std::move(stmts)), loc(loc)
  {
  }
  std::unique_ptr<Expression> cond;
  std::unique_ptr<StatementList> stmts = nullptr;
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
  std::string name(const std::string &attach_target,
                   const std::string &attach_point) const;

  int index(std::string name);
  void set_index(std::string name, int index);
private:
  std::map<std::string, int> index_;
};
using AttachPointList = std::vector<std::unique_ptr<AttachPoint>>;

class Probe : public Node {
public:
  Probe(std::unique_ptr<AttachPointList> attach_points,
        std::unique_ptr<Predicate> pred,
        std::unique_ptr<StatementList> stmts);

  std::unique_ptr<AttachPointList> attach_points;
  std::unique_ptr<Predicate> pred;
  std::unique_ptr<StatementList> stmts;

  void accept(Visitor &v) override;
  std::string name() const;
  bool need_expansion = false;        // must build a BPF program per wildcard match
  bool need_tp_args_structs = false;  // must import struct for tracepoints

  int index();
  void set_index(int index);
private:
  int index_ = 0;
};
using ProbeList = std::vector<std::unique_ptr<Probe>>;

class Program : public Node {
public:
  Program(const std::string &c_definitions, std::unique_ptr<ProbeList> probes);
  std::string c_definitions;
  std::unique_ptr<ProbeList> probes;

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
  virtual void visit(Tuple &tuple) = 0;
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
