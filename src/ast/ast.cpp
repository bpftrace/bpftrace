#include "ast.h"
#include "log.h"
#include "parser.tab.hh"
#include <iostream>

namespace bpftrace {
namespace ast {

Node::Node() : loc(location())
{
}

Node::Node(location loc) : loc(loc)
{
}

Expression::Expression() : Node()
{
}

Expression::Expression(location loc) : Node(loc)
{
}

Integer::Integer(long n) : n(n)
{
  is_literal = true;
}

Integer::Integer(long n, location loc) : Expression(loc), n(n)
{
  is_literal = true;
}

void Integer::accept(Visitor &v) {
  v.visit(*this);
}

String::String(const std::string &str) : str(str)
{
  is_literal = true;
}

String::String(const std::string &str, location loc) : Expression(loc), str(str)
{
  is_literal = true;
}

void String::accept(Visitor &v) {
  v.visit(*this);
}

StackMode::StackMode(const std::string &mode) : mode(mode)
{
  is_literal = true;
}

StackMode::StackMode(const std::string &mode, location loc)
    : Expression(loc), mode(mode)
{
  is_literal = true;
}

void StackMode::accept(Visitor &v) {
  v.visit(*this);
}

Builtin::Builtin(const std::string &ident) : ident(is_deprecated(ident))
{
}

Builtin::Builtin(const std::string &ident, location loc)
    : Expression(loc), ident(is_deprecated(ident))
{
}

void Builtin::accept(Visitor &v) {
  v.visit(*this);
}

Identifier::Identifier(const std::string &ident) : ident(ident)
{
}

Identifier::Identifier(const std::string &ident, location loc)
    : Expression(loc), ident(ident)
{
}

void Identifier::accept(Visitor &v) {
  v.visit(*this);
}

PositionalParameter::PositionalParameter(PositionalParameterType ptype, long n)
    : ptype(ptype), n(n)
{
  is_literal = true;
}

PositionalParameter::PositionalParameter(PositionalParameterType ptype,
                                         long n,
                                         location loc)
    : Expression(loc), ptype(ptype), n(n)
{
  is_literal = true;
}

void PositionalParameter::accept(Visitor &v) {
  v.visit(*this);
}

Call::Call(const std::string &func) : func(is_deprecated(func)), vargs(nullptr)
{
}

Call::Call(const std::string &func, location loc)
    : Expression(loc), func(is_deprecated(func)), vargs(nullptr)
{
}

Call::Call(const std::string &func, std::unique_ptr<ExpressionList> vargs)
    : func(is_deprecated(func)), vargs(std::move(vargs))
{
}

Call::Call(const std::string &func,
           std::unique_ptr<ExpressionList> vargs,
           location loc)
    : Expression(loc), func(is_deprecated(func)), vargs(std::move(vargs))
{
}

void Call::accept(Visitor &v) {
  v.visit(*this);
}

Map::Map(const std::string &ident, location loc)
    : Expression(loc), ident(ident), vargs(nullptr)
{
  is_map = true;
}

Map::Map(const std::string &ident, std::unique_ptr<ExpressionList> vargs)
    : ident(ident), vargs(std::move(vargs))
{
  is_map = true;
}

Map::Map(const std::string &ident,
         std::unique_ptr<ExpressionList> vargs,
         location loc)
    : Expression(loc), ident(ident), vargs(std::move(vargs))
{
  is_map = true;
  for (auto &expr : *this->vargs)
  {
    expr->key_for_map = this;
  }
}

Map::Map(const Map &m) : Expression(m.loc), ident(m.ident)
{
  is_map = true;
  // TODO(oazizi): This will break things if m.vargs is not empty.
}

void Map::accept(Visitor &v) {
  v.visit(*this);
}

Variable::Variable(const std::string &ident) : ident(ident)
{
  is_variable = true;
}

Variable::Variable(const std::string &ident, location loc)
    : Expression(loc), ident(ident)
{
  is_variable = true;
}

Variable::Variable(const Variable &var) : Expression(var.loc), ident(var.ident)
{
  is_variable = true;
}

void Variable::accept(Visitor &v) {
  v.visit(*this);
}

Binop::Binop(std::unique_ptr<Expression> left,
             int op,
             std::unique_ptr<Expression> right,
             location loc)
    : Expression(loc), left(std::move(left)), right(std::move(right)), op(op)
{
}

void Binop::accept(Visitor &v) {
  v.visit(*this);
}

Unop::Unop(int op, std::unique_ptr<Expression> expr, location loc)
    : Expression(loc), expr(std::move(expr)), op(op), is_post_op(false)
{
}

Unop::Unop(int op,
           std::unique_ptr<Expression> expr,
           bool is_post_op,
           location loc)
    : Expression(loc), expr(std::move(expr)), op(op), is_post_op(is_post_op)
{
}

void Unop::accept(Visitor &v) {
  v.visit(*this);
}

Ternary::Ternary(std::unique_ptr<Expression> cond,
                 std::unique_ptr<Expression> left,
                 std::unique_ptr<Expression> right)
    : cond(std::move(cond)), left(std::move(left)), right(std::move(right))
{
}

Ternary::Ternary(std::unique_ptr<Expression> cond,
                 std::unique_ptr<Expression> left,
                 std::unique_ptr<Expression> right,
                 location loc)
    : Expression(loc),
      cond(std::move(cond)),
      left(std::move(left)),
      right(std::move(right))
{
}

void Ternary::accept(Visitor &v) {
  v.visit(*this);
}

FieldAccess::FieldAccess(std::unique_ptr<Expression> expr,
                         const std::string &field)
    : expr(std::move(expr)), field(field)
{
}

FieldAccess::FieldAccess(std::unique_ptr<Expression> expr,
                         const std::string &field,
                         location loc)
    : Expression(loc), expr(std::move(expr)), field(field)
{
}

FieldAccess::FieldAccess(std::unique_ptr<Expression> expr,
                         ssize_t index,
                         location loc)
    : Expression(loc), expr(std::move(expr)), index(index)
{
}

void FieldAccess::accept(Visitor &v) {
  v.visit(*this);
}

ArrayAccess::ArrayAccess(std::unique_ptr<Expression> expr,
                         std::unique_ptr<Expression> indexpr)
    : expr(std::move(expr)), indexpr(std::move(indexpr))
{
}

ArrayAccess::ArrayAccess(std::unique_ptr<Expression> expr,
                         std::unique_ptr<Expression> indexpr,
                         location loc)
    : Expression(loc), expr(std::move(expr)), indexpr(std::move(indexpr))
{
}

void ArrayAccess::accept(Visitor &v) {
  v.visit(*this);
}

Cast::Cast(const std::string &type,
           bool is_pointer,
           std::unique_ptr<Expression> expr)
    : cast_type(type), is_pointer(is_pointer), expr(std::move(expr))
{
}

Cast::Cast(const std::string &type,
           bool is_pointer,
           std::unique_ptr<Expression> expr,
           location loc)
    : Expression(loc),
      cast_type(type),
      is_pointer(is_pointer),
      expr(std::move(expr))
{
}

void Cast::accept(Visitor &v) {
  v.visit(*this);
}

Tuple::Tuple(std::unique_ptr<ExpressionList> elems, location loc)
    : Expression(loc), elems(std::move(elems))
{
}

void Tuple::accept(Visitor &v)
{
  v.visit(*this);
}

Statement::Statement(location loc) : Node(loc)
{
}

ExprStatement::ExprStatement(std::unique_ptr<Expression> expr)
    : expr(std::move(expr))
{
}

ExprStatement::ExprStatement(std::unique_ptr<Expression> expr, location loc)
    : Statement(loc), expr(std::move(expr))
{
}

void ExprStatement::accept(Visitor &v) {
  v.visit(*this);
}

AssignMapStatement::AssignMapStatement(std::unique_ptr<Map> map,
                                       std::unique_ptr<Expression> expr,
                                       location loc)
    : Statement(loc), map(std::move(map)), expr(std::move(expr))
{
  this->expr->map = this->map.get();
};

void AssignMapStatement::accept(Visitor &v) {
  v.visit(*this);
}

AssignVarStatement::AssignVarStatement(std::unique_ptr<Variable> var,
                                       std::unique_ptr<Expression> expr)
    : var(std::move(var)), expr(std::move(expr))
{
  this->expr->var = this->var.get();
}

AssignVarStatement::AssignVarStatement(std::unique_ptr<Variable> var,
                                       std::unique_ptr<Expression> expr,
                                       location loc)
    : Statement(loc), var(std::move(var)), expr(std::move(expr))
{
  this->expr->var = this->var.get();
}

void AssignVarStatement::accept(Visitor &v) {
  v.visit(*this);
}

Predicate::Predicate(std::unique_ptr<Expression> expr) : expr(std::move(expr))
{
}

Predicate::Predicate(std::unique_ptr<Expression> expr, location loc)
    : Node(loc), expr(std::move(expr))
{
}

void Predicate::accept(Visitor &v) {
  v.visit(*this);
}

AttachPoint::AttachPoint(const std::string &raw_input, location loc)
    : Node(loc), raw_input(raw_input)
{
}

void AttachPoint::accept(Visitor &v) {
  v.visit(*this);
}

If::If(std::unique_ptr<Expression> cond, std::unique_ptr<StatementList> stmts)
    : cond(std::move(cond)), stmts(std::move(stmts))
{
}

If::If(std::unique_ptr<Expression> cond,
       std::unique_ptr<StatementList> stmts,
       std::unique_ptr<StatementList> else_stmts)
    : cond(std::move(cond)),
      stmts(std::move(stmts)),
      else_stmts(std::move(else_stmts))
{
}

void If::accept(Visitor &v) {
  v.visit(*this);
}

Unroll::Unroll(std::unique_ptr<Expression> expr,
               std::unique_ptr<StatementList> stmts,
               location loc)
    : Statement(loc), expr(std::move(expr)), stmts(std::move(stmts))
{
}

void Unroll::accept(Visitor &v) {
  v.visit(*this);
}

Probe::Probe(std::unique_ptr<AttachPointList> attach_points,
             std::unique_ptr<Predicate> pred,
             std::unique_ptr<StatementList> stmts)
    : attach_points(std::move(attach_points)),
      pred(std::move(pred)),
      stmts(std::move(stmts))
{
}

void While::accept(Visitor &v)
{
  v.visit(*this);
}

void Jump::accept(Visitor &v)
{
  v.visit(*this);
}

void Probe::accept(Visitor &v) {
  v.visit(*this);
}

Program::Program(const std::string &c_definitions,
                 std::unique_ptr<ProbeList> probes)
    : c_definitions(c_definitions), probes(std::move(probes))
{
}

void Program::accept(Visitor &v) {
  v.visit(*this);
}

std::string opstr(Jump &jump)
{
  switch (jump.ident)
  {
    case bpftrace::Parser::token::RETURN:
      return "return";
    case bpftrace::Parser::token::BREAK:
      return "break";
    case bpftrace::Parser::token::CONTINUE:
      return "continue";
  }

  return {}; // unreached
}

std::string opstr(Binop &binop)
{
  switch (binop.op) {
    case bpftrace::Parser::token::EQ:    return "==";
    case bpftrace::Parser::token::NE:    return "!=";
    case bpftrace::Parser::token::LE:    return "<=";
    case bpftrace::Parser::token::GE:    return ">=";
    case bpftrace::Parser::token::LT:    return "<";
    case bpftrace::Parser::token::GT:    return ">";
    case bpftrace::Parser::token::LAND:  return "&&";
    case bpftrace::Parser::token::LOR:   return "||";
    case bpftrace::Parser::token::LEFT:  return "<<";
    case bpftrace::Parser::token::RIGHT: return ">>";
    case bpftrace::Parser::token::PLUS:  return "+";
    case bpftrace::Parser::token::MINUS: return "-";
    case bpftrace::Parser::token::MUL:   return "*";
    case bpftrace::Parser::token::DIV:   return "/";
    case bpftrace::Parser::token::MOD:   return "%";
    case bpftrace::Parser::token::BAND:  return "&";
    case bpftrace::Parser::token::BOR:   return "|";
    case bpftrace::Parser::token::BXOR:  return "^";
  }

  return {}; // unreached
}

std::string opstr(Unop &unop)
{
  switch (unop.op) {
    case bpftrace::Parser::token::LNOT: return "!";
    case bpftrace::Parser::token::BNOT: return "~";
    case bpftrace::Parser::token::MINUS: return "-";
    case bpftrace::Parser::token::MUL: return "dereference";
    case bpftrace::Parser::token::INCREMENT: return "++";
    case bpftrace::Parser::token::DECREMENT: return "--";
  }

  return {}; // unreached
}

std::string AttachPoint::name(const std::string &attach_target,
                              const std::string &attach_point) const
{
  std::string n = provider;
  if (attach_target != "")
    n += ":" + attach_target;
  if (ns != "")
    n += ":" + ns;
  if (attach_point != "")
  {
    n += ":" + attach_point;
    if (func_offset != 0)
      n += "+" + std::to_string(func_offset);
  }
  if (address != 0)
    n += ":" + std::to_string(address);
  if (freq != 0)
    n += ":" + std::to_string(freq);
  if (len != 0)
    n += ":" + std::to_string(len);
  if (mode.size())
    n += ":" + mode;
  return n;
}

std::string AttachPoint::name(const std::string &attach_point) const
{
  return name(target, attach_point);
}

int AttachPoint::index(std::string name) {
  if (index_.count(name) == 0) return 0;
  return index_[name];
}

void AttachPoint::set_index(std::string name, int index) {
  index_[name] = index;
}

std::string Probe::name() const
{
  std::string n;
  for (auto &attach_point : *attach_points)
  {
    if (!n.empty())
      n += ',';
    n += attach_point->provider;
    if (attach_point->target != "")
      n += ":" + attach_point->target;
    if (attach_point->ns != "")
      n += ":" + attach_point->ns;
    if (attach_point->func != "")
    {
      n += ":" + attach_point->func;
      if (attach_point->func_offset != 0)
        n += "+" + std::to_string(attach_point->func_offset);
    }
    if (attach_point->address != 0)
      n += ":" + std::to_string(attach_point->address);
    if (attach_point->freq != 0)
      n += ":" + std::to_string(attach_point->freq);
  }
  return n;
}

int Probe::index() {
  return index_;
}

void Probe::set_index(int index) {
  index_ = index;
}

} // namespace ast
} // namespace bpftrace
