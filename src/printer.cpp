#include "printer.h"
#include "ast.h"
#include "parser.tab.hh"

namespace ebpf {
namespace bpftrace {
namespace ast {

void Printer::visit(Integer &integer)
{
  std::string indent(depth_, ' ');
  out_ << indent << "int: " << integer.n << std::endl;
}

void Printer::visit(Variable &var)
{
  std::string indent(depth_, ' ');
  out_ << indent << "var: " << var.ident << std::endl;
}

void Printer::visit(Binop &binop)
{
  std::string indent(depth_, ' ');
  std::string opstr;
  switch (binop.op) {
    case ebpf::bpftrace::Parser::token::EQ:
      opstr = "==";
      break;
    case ebpf::bpftrace::Parser::token::NE:
      opstr = "!=";
      break;
    case ebpf::bpftrace::Parser::token::LE:
      opstr = "<=";
      break;
    case ebpf::bpftrace::Parser::token::GE:
      opstr = ">=";
      break;
    case ebpf::bpftrace::Parser::token::LT:
      opstr = "<";
      break;
    case ebpf::bpftrace::Parser::token::GT:
      opstr = ">";
      break;
    case ebpf::bpftrace::Parser::token::LAND:
      opstr = "&&";
      break;
    case ebpf::bpftrace::Parser::token::LOR:
      opstr = "||";
      break;
    case ebpf::bpftrace::Parser::token::PLUS:
      opstr = "+";
      break;
    case ebpf::bpftrace::Parser::token::MINUS:
      opstr = "-";
      break;
    case ebpf::bpftrace::Parser::token::MUL:
      opstr = "*";
      break;
    case ebpf::bpftrace::Parser::token::DIV:
      opstr = "/";
      break;
    case ebpf::bpftrace::Parser::token::MOD:
      opstr = "%";
      break;
    case ebpf::bpftrace::Parser::token::BAND:
      opstr = "&";
      break;
    case ebpf::bpftrace::Parser::token::BOR:
      opstr = "|";
      break;
    case ebpf::bpftrace::Parser::token::BXOR:
      opstr = "^";
      break;
    default:
      opstr = "???";
      break;
  }

  out_ << indent << opstr << std::endl;
}

void Printer::visit(Unop &unop)
{
  std::string indent(depth_, ' ');
  std::string opstr;
  switch (unop.op) {
    case ebpf::bpftrace::Parser::token::LNOT:
      opstr = "!";
      break;
    case ebpf::bpftrace::Parser::token::BNOT:
      opstr = "~";
      break;
    default:
      opstr = "???";
      break;
  }

  out_ << indent << opstr << std::endl;
}

void Printer::visit(ExprStatement &)
{
}

void Printer::visit(AssignStatement &)
{
  std::string indent(depth_, ' ');
  out_ << indent << "=" << std::endl;
}

void Printer::visit(Probe &probe)
{
  std::string indent(depth_, ' ');
  out_ << indent << probe.type << ":" << probe.attach_point << std::endl;
  if (probe.pred) {
    out_ << indent << " pred";
  }
}

void Printer::visit(Program &)
{
  std::string indent(depth_, ' ');
  out_ << indent << "Program" << std::endl;
}

} // namespace ast
} // namespace bpftrace
} // namespace ebpf
