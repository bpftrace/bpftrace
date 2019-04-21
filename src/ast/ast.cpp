#include "ast.h"
#include "parser.tab.hh"
#include <iostream>

namespace bpftrace {
namespace ast {

void Integer::accept(Visitor &v) {
  v.visit(*this);
}

void String::accept(Visitor &v) {
  v.visit(*this);
}

void StackMode::accept(Visitor &v) {
  v.visit(*this);
}

void Builtin::accept(Visitor &v) {
  v.visit(*this);
}

void Identifier::accept(Visitor &v) {
  v.visit(*this);
}

void PositionalParameter::accept(Visitor &v) {
  v.visit(*this);
}

void Call::accept(Visitor &v) {
  v.visit(*this);
}

void Map::accept(Visitor &v) {
  v.visit(*this);
}

void Variable::accept(Visitor &v) {
  v.visit(*this);
}

void Binop::accept(Visitor &v) {
  v.visit(*this);
}

void Unop::accept(Visitor &v) {
  v.visit(*this);
}

void Ternary::accept(Visitor &v) {
  v.visit(*this);
}

void FieldAccess::accept(Visitor &v) {
  v.visit(*this);
}

void ArrayAccess::accept(Visitor &v) {
  v.visit(*this);
}

void Cast::accept(Visitor &v) {
  v.visit(*this);
}

void ExprStatement::accept(Visitor &v) {
  v.visit(*this);
}

void AssignMapStatement::accept(Visitor &v) {
  v.visit(*this);
}

void AssignVarStatement::accept(Visitor &v) {
  v.visit(*this);
}

void Predicate::accept(Visitor &v) {
  v.visit(*this);
}

void AttachPoint::accept(Visitor &v) {
  v.visit(*this);
}

void If::accept(Visitor &v) {
  v.visit(*this);
}

void Unroll::accept(Visitor &v) {
  v.visit(*this);
}

void Probe::accept(Visitor &v) {
  v.visit(*this);
}

void Program::accept(Visitor &v) {
  v.visit(*this);
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
    case bpftrace::Parser::token::MUL:  return "dereference";
    default:
      std::cerr << "unknown union operator" << std::endl;
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
    n += ":" + attach_point;
  if (freq != 0)
    n += ":" + std::to_string(freq);
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
      n += ":" + attach_point->func;
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
