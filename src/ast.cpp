#include "ast.h"
#include "parser.tab.hh"

namespace ebpf {
namespace bpftrace {
namespace ast {

void Integer::print_ast(std::ostream &out, unsigned int depth) const
{
  std::string indent(depth, ' ');
  out << indent << "int: " << n << std::endl;
}

void Variable::print_ast(std::ostream &out, unsigned int depth) const
{
  std::string indent(depth, ' ');
  out << indent << "var: " << ident << std::endl;
  if (vargs) {
    for (Expression *expr : *vargs) {
      expr->print_ast(out, depth+1);
    }
  }
}

void Binop::print_ast(std::ostream &out, unsigned int depth) const
{
  std::string indent(depth, ' ');
  std::string opstr;
  switch (op) {
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

  out << indent << opstr << std::endl;
  left->print_ast(out, depth+1);
  right->print_ast(out, depth+1);
}

void Unop::print_ast(std::ostream &out, unsigned int depth) const
{
  std::string indent(depth, ' ');
  std::string opstr;
  switch (op) {
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

  out << indent << opstr << std::endl;
  expr->print_ast(out, depth+1);
}

void ExprStatement::print_ast(std::ostream &out, unsigned int depth) const
{
  std::string indent(depth, ' ');
  expr->print_ast(out, depth);
}

void AssignStatement::print_ast(std::ostream &out, unsigned int depth) const
{
  std::string indent(depth, ' ');
  out << indent << "=" << std::endl;
  var->print_ast(out, depth+1);
  expr->print_ast(out, depth+1);
}

void Probe::print_ast(std::ostream &out, unsigned int depth) const
{
  std::string indent(depth, ' ');
  out << indent << type << ":" << attach_point << std::endl;
  out << indent << " pred" << std::endl;
  if (pred) {
    pred->print_ast(out, depth+2);
  }
  for (Statement *stmt : *stmts) {
    stmt->print_ast(out, depth+1);
  }
}

void Program::print_ast(std::ostream &out, unsigned int depth) const
{
  std::string indent(depth, ' ');
  out << indent << "Program" << std::endl;
  for (Probe *probe : *probes) {
    probe->print_ast(out, depth+1);
  }
}

} // namespace ast
} // namespace bpftrace
} // namespace ebpf
