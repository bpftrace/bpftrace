#include "ast.h"
#include "parser.tab.hh"

namespace ebpf {
namespace bpftrace {
namespace ast {

void Integer::accept(Visitor &v) {
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

void AssignMapCallStatement::accept(Visitor &v) {
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
    case ebpf::bpftrace::Parser::token::EQ:    return "==";
    case ebpf::bpftrace::Parser::token::NE:    return "!=";
    case ebpf::bpftrace::Parser::token::LE:    return "<=";
    case ebpf::bpftrace::Parser::token::GE:    return ">=";
    case ebpf::bpftrace::Parser::token::LT:    return "<";
    case ebpf::bpftrace::Parser::token::GT:    return ">";
    case ebpf::bpftrace::Parser::token::LAND:  return "&&";
    case ebpf::bpftrace::Parser::token::LOR:   return "||";
    case ebpf::bpftrace::Parser::token::PLUS:  return "+";
    case ebpf::bpftrace::Parser::token::MINUS: return "-";
    case ebpf::bpftrace::Parser::token::MUL:   return "*";
    case ebpf::bpftrace::Parser::token::DIV:   return "/";
    case ebpf::bpftrace::Parser::token::MOD:   return "%";
    case ebpf::bpftrace::Parser::token::BAND:  return "&";
    case ebpf::bpftrace::Parser::token::BOR:   return "|";
    case ebpf::bpftrace::Parser::token::BXOR:  return "^";
    default: abort();
  }
}

std::string opstr(Unop &unop)
{
  switch (unop.op) {
    case ebpf::bpftrace::Parser::token::LNOT: return "!";
    case ebpf::bpftrace::Parser::token::BNOT: return "~";
    default: abort();
  }
}

} // namespace ast
} // namespace bpftrace
} // namespace ebpf
