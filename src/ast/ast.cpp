#include "ast.h"
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

Call::Call(const std::string &func, location loc, ExpressionList *vargs)
    : Expression(loc), func(is_deprecated(func)), vargs(vargs)
{
}

void Call::accept(Visitor &v) {
  v.visit(*this);
}

StrCall::StrCall(location loc, ExpressionList *vargs)
    : Call("str", std::move(loc), vargs)
{
}

void StrCall::initialise(std::unique_ptr<IMap> map, std::unique_ptr<RingIndexer> ringIndexer) {
  this->map.swap(map);
  this->ringIndexer.swap(ringIndexer);
  this->initialised = true;
}

Call* CallFactory::createCall(const std::string &func, location loc, ExpressionList *vargs) {
  if (func == "str") {
    return new StrCall(std::move(loc), vargs);
  }
  return new Call(func, std::move(loc), vargs);
}

Map::Map(const std::string &ident, location loc)
    : Expression(loc), ident(ident), vargs(nullptr)
{
  is_map = true;
}

Map::Map(const std::string &ident, ExpressionList *vargs)
    : ident(ident), vargs(vargs)
{
  is_map = true;
}

Map::Map(const std::string &ident, ExpressionList *vargs, location loc)
    : Expression(loc), ident(ident), vargs(vargs)
{
  is_map = true;
  for (auto expr : *vargs)
  {
    expr->key_for_map = this;
  }
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

void Variable::accept(Visitor &v) {
  v.visit(*this);
}

Binop::Binop(Expression *left, int op, Expression *right, location loc)
    : Expression(loc), left(left), right(right), op(op)
{
}

void Binop::accept(Visitor &v) {
  v.visit(*this);
}

Unop::Unop(int op, Expression *expr, location loc)
    : Expression(loc), expr(expr), op(op), is_post_op(false)
{
}

Unop::Unop(int op, Expression *expr, bool is_post_op, location loc)
    : Expression(loc), expr(expr), op(op), is_post_op(is_post_op)
{
}

void Unop::accept(Visitor &v) {
  v.visit(*this);
}

Ternary::Ternary(Expression *cond, Expression *left, Expression *right)
    : cond(cond), left(left), right(right)
{
}

Ternary::Ternary(Expression *cond,
                 Expression *left,
                 Expression *right,
                 location loc)
    : Expression(loc), cond(cond), left(left), right(right)
{
}

void Ternary::accept(Visitor &v) {
  v.visit(*this);
}

FieldAccess::FieldAccess(Expression *expr, const std::string &field)
    : expr(expr), field(field)
{
}

FieldAccess::FieldAccess(Expression *expr,
                         const std::string &field,
                         location loc)
    : Expression(loc), expr(expr), field(field)
{
}

void FieldAccess::accept(Visitor &v) {
  v.visit(*this);
}

ArrayAccess::ArrayAccess(Expression *expr, Expression *indexpr)
    : expr(expr), indexpr(indexpr)
{
}

ArrayAccess::ArrayAccess(Expression *expr, Expression *indexpr, location loc)
    : Expression(loc), expr(expr), indexpr(indexpr)
{
}

void ArrayAccess::accept(Visitor &v) {
  v.visit(*this);
}

Cast::Cast(const std::string &type, bool is_pointer, Expression *expr)
    : cast_type(type), is_pointer(is_pointer), expr(expr)
{
}

Cast::Cast(const std::string &type,
           bool is_pointer,
           Expression *expr,
           location loc)
    : Expression(loc), cast_type(type), is_pointer(is_pointer), expr(expr)
{
}

void Cast::accept(Visitor &v) {
  v.visit(*this);
}

Statement::Statement(location loc) : Node(loc)
{
}

ExprStatement::ExprStatement(Expression *expr) : expr(expr)
{
}

ExprStatement::ExprStatement(Expression *expr, location loc)
    : Statement(loc), expr(expr)
{
}

void ExprStatement::accept(Visitor &v) {
  v.visit(*this);
}

AssignMapStatement::AssignMapStatement(Map *map, Expression *expr, location loc)
    : Statement(loc), map(map), expr(expr)
{
  expr->map = map;
};

void AssignMapStatement::accept(Visitor &v) {
  v.visit(*this);
}

AssignVarStatement::AssignVarStatement(Variable *var, Expression *expr)
    : var(var), expr(expr)
{
  expr->var = var;
}

AssignVarStatement::AssignVarStatement(Variable *var,
                                       Expression *expr,
                                       location loc)
    : Statement(loc), var(var), expr(expr)
{
  expr->var = var;
}

void AssignVarStatement::accept(Visitor &v) {
  v.visit(*this);
}

Predicate::Predicate(Expression *expr) : expr(expr)
{
}

Predicate::Predicate(Expression *expr, location loc) : Node(loc), expr(expr)
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

If::If(Expression *cond, StatementList *stmts) : cond(cond), stmts(stmts)
{
}

If::If(Expression *cond, StatementList *stmts, StatementList *else_stmts)
    : cond(cond), stmts(stmts), else_stmts(else_stmts)
{
}

void If::accept(Visitor &v) {
  v.visit(*this);
}

Unroll::Unroll(Expression *expr, StatementList *stmts, location loc)
    : Statement(loc), expr(expr), stmts(stmts)
{
}

void Unroll::accept(Visitor &v) {
  v.visit(*this);
}

Probe::Probe(AttachPointList *attach_points,
             Predicate *pred,
             StatementList *stmts)
    : attach_points(attach_points), pred(pred), stmts(stmts)
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

Program::Program(const std::string &c_definitions, ProbeList *probes)
    : c_definitions(c_definitions), probes(probes)
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
    default:
      throw std::runtime_error("Unknown jump");
  }
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
    default:
      std::cerr << "unknown binary operator" << std::endl;
      abort();
  }
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
    default:
      std::cerr << "unknown unary operator" << std::endl;
      abort();
  }
}

std::string AttachPoint::name(const std::string &attach_point) const
{
  std::string n = provider;
  if (target != "")
    n += ":" + target;
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
