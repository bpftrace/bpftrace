#include "ast.h"
#include "log.h"
#include "parser.tab.hh"
#include "visitors.h"
#include <iostream>

namespace bpftrace {
namespace ast {

#define MAKE_ACCEPT(Ty)                                                        \
  void Ty::accept(Visitor &v)                                                  \
  {                                                                            \
    v.visit(*this);                                                            \
  };

MAKE_ACCEPT(Integer)
MAKE_ACCEPT(String)
MAKE_ACCEPT(StackMode)
MAKE_ACCEPT(Builtin)
MAKE_ACCEPT(Identifier)
MAKE_ACCEPT(PositionalParameter)
MAKE_ACCEPT(Call)
MAKE_ACCEPT(Map)
MAKE_ACCEPT(Variable)
MAKE_ACCEPT(Binop)
MAKE_ACCEPT(Unop)
MAKE_ACCEPT(Ternary)
MAKE_ACCEPT(FieldAccess)
MAKE_ACCEPT(ArrayAccess)
MAKE_ACCEPT(Cast)
MAKE_ACCEPT(Tuple)
MAKE_ACCEPT(ExprStatement)
MAKE_ACCEPT(AssignMapStatement)
MAKE_ACCEPT(AssignVarStatement)
MAKE_ACCEPT(Predicate)
MAKE_ACCEPT(AttachPoint)
MAKE_ACCEPT(If)
MAKE_ACCEPT(Unroll)
MAKE_ACCEPT(While)
MAKE_ACCEPT(Jump)
MAKE_ACCEPT(Probe)
MAKE_ACCEPT(Program)

#undef MAKE_ACCEPT

Integer::Integer(long n, location loc) : Expression(loc), n(n)
{
  is_literal = true;
}


String::String(const std::string &str, location loc) : Expression(loc), str(str)
{
  is_literal = true;
}


StackMode::StackMode(const std::string &mode, location loc)
    : Expression(loc), mode(mode)
{
  is_literal = true;
}


Builtin::Builtin(const std::string &ident, location loc)
    : Expression(loc), ident(is_deprecated(ident))
{
}


Identifier::Identifier(const std::string &ident, location loc)
    : Expression(loc), ident(ident)
{
}


PositionalParameter::PositionalParameter(PositionalParameterType ptype,
                                         long n,
                                         location loc)
    : Expression(loc), ptype(ptype), n(n)
{
  is_literal = true;
}


Call::Call(const std::string &func, location loc)
    : Expression(loc), func(is_deprecated(func)), vargs(nullptr)
{
}

Call::Call(const std::string &func, ExpressionList *vargs, location loc)
    : Expression(loc), func(is_deprecated(func)), vargs(vargs)
{
}

Map::Map(const std::string &ident, location loc)
    : Expression(loc), ident(ident), vargs(nullptr)
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

Variable::Variable(const std::string &ident, location loc)
    : Expression(loc), ident(ident)
{
  is_variable = true;
}

Binop::Binop(Expression *left, int op, Expression *right, location loc)
    : Expression(loc), left(left), right(right), op(op)
{
}


Unop::Unop(int op, Expression *expr, location loc)
    : Expression(loc), expr(expr), op(op), is_post_op(false)
{
}

Unop::Unop(int op, Expression *expr, bool is_post_op, location loc)
    : Expression(loc), expr(expr), op(op), is_post_op(is_post_op)
{
}


Ternary::Ternary(Expression *cond,
                 Expression *left,
                 Expression *right,
                 location loc)
    : Expression(loc), cond(cond), left(left), right(right)
{
}


FieldAccess::FieldAccess(Expression *expr,
                         const std::string &field,
                         location loc)
    : Expression(loc), expr(expr), field(field)
{
}

FieldAccess::FieldAccess(Expression *expr, ssize_t index, location loc)
    : Expression(loc), expr(expr), index(index)
{
}


ArrayAccess::ArrayAccess(Expression *expr, Expression *indexpr, location loc)
    : Expression(loc), expr(expr), indexpr(indexpr)
{
}


Cast::Cast(const std::string &type,
           bool is_pointer,
           bool is_double_pointer,
           Expression *expr,
           location loc)
    : Expression(loc),
      cast_type(type),
      is_pointer(is_pointer),
      is_double_pointer(is_double_pointer),
      expr(expr)
{
}


Tuple::Tuple(ExpressionList *elems, location loc)
    : Expression(loc), elems(elems)
{
}


ExprStatement::ExprStatement(Expression *expr, location loc)
    : Statement(loc), expr(expr)
{
}


AssignMapStatement::AssignMapStatement(Map *map, Expression *expr, location loc)
    : Statement(loc), map(map), expr(expr)
{
  expr->map = map;
};


AssignVarStatement::AssignVarStatement(Variable *var,
                                       Expression *expr,
                                       location loc)
    : Statement(loc), var(var), expr(expr)
{
  expr->var = var;
}


Predicate::Predicate(Expression *expr, location loc) : Node(loc), expr(expr)
{
}


AttachPoint::AttachPoint(const std::string &raw_input, location loc)
    : Node(loc), raw_input(raw_input)
{
}


If::If(Expression *cond, StatementList *stmts) : cond(cond), stmts(stmts)
{
}

If::If(Expression *cond, StatementList *stmts, StatementList *else_stmts)
    : cond(cond), stmts(stmts), else_stmts(else_stmts)
{
}


Unroll::Unroll(Expression *expr, StatementList *stmts, location loc)
    : Statement(loc), expr(expr), stmts(stmts)
{
}

Probe::Probe(AttachPointList *attach_points,
             Predicate *pred,
             StatementList *stmts)
    : attach_points(attach_points), pred(pred), stmts(stmts)
{
}


Program::Program(const std::string &c_definitions, ProbeList *probes)
    : c_definitions(c_definitions), probes(probes)
{
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

Expression::Expression(const Expression &other) : Node(other)
{
  type = other.type;
  is_literal = other.is_literal;
  is_variable = other.is_variable;
  is_map = other.is_map;
}

Call::Call(const Call &other) : Expression(other)
{
  func = other.func;
}

Binop::Binop(const Binop &other) : Expression(other)
{
  op = other.op;
}

Unop::Unop(const Unop &other) : Expression(other)
{
  op = other.op;
  is_post_op = other.is_post_op;
}

Map::Map(const Map &other) : Expression(other)
{
  ident = other.ident;
  skip_key_validation = other.skip_key_validation;
}

FieldAccess::FieldAccess(const FieldAccess &other)
    : Expression(other), expr(nullptr)
{
  field = other.field;
  index = other.index;
}

Unroll::Unroll(const Unroll &other) : Statement(other)
{
  var = other.var;
}

Program::Program(const Program &other) : Node(other)
{
  c_definitions = other.c_definitions;
}

Cast::Cast(const Cast &other) : Expression(other)
{
  cast_type = other.cast_type;
  is_pointer = other.is_pointer;
  is_double_pointer = other.is_double_pointer;
}

Probe::Probe(const Probe &other) : Node(other)
{
  need_expansion = other.need_expansion;
  need_tp_args_structs = other.need_tp_args_structs;
  index_ = other.index_;
}

While::While(const While &other) : Statement(other)
{
}

Tuple::Tuple(const Tuple &other) : Expression(other)
{
}

If::If(const If &other) : Statement(other)
{
}

} // namespace ast
} // namespace bpftrace
