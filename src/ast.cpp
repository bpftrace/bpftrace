#include "ast.h"
#include "parser.tab.hh"

namespace bpftrace {
namespace ast {

void Integer::accept(Visitor &v) {
  v.visit(*this);
}

void String::accept(Visitor &v) {
  v.visit(*this);
}

void Builtin::accept(Visitor &v) {
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
    case bpftrace::Parser::token::PLUS:  return "+";
    case bpftrace::Parser::token::MINUS: return "-";
    case bpftrace::Parser::token::MUL:   return "*";
    case bpftrace::Parser::token::DIV:   return "/";
    case bpftrace::Parser::token::MOD:   return "%";
    case bpftrace::Parser::token::BAND:  return "&";
    case bpftrace::Parser::token::BOR:   return "|";
    case bpftrace::Parser::token::BXOR:  return "^";
    default: abort();
  }
}

std::string opstr(Unop &unop)
{
  switch (unop.op) {
    case bpftrace::Parser::token::LNOT: return "!";
    case bpftrace::Parser::token::BNOT: return "~";
    case bpftrace::Parser::token::MUL:  return "dereference";
    default: abort();
  }
}

} // namespace ast
} // namespace bpftrace
