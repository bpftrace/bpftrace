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

void Printer::visit(Builtin &builtin)
{
  std::string indent(depth_, ' ');
  out_ << indent << "builtin: " << builtin.ident << std::endl;
}

void Printer::visit(Call &call)
{
  std::string indent(depth_, ' ');
  out_ << indent << "call: " << call.func << std::endl;

  ++depth_;
  if (call.vargs) {
    for (Expression *expr : *call.vargs) {
      expr->accept(*this);
    }
  }
  --depth_;
}

void Printer::visit(Map &map)
{
  std::string indent(depth_, ' ');
  out_ << indent << "map: " << map.ident << std::endl;

  ++depth_;
  if (map.vargs) {
    for (Expression *expr : *map.vargs) {
      expr->accept(*this);
    }
  }
  --depth_;
}

void Printer::visit(Binop &binop)
{
  std::string indent(depth_, ' ');
  std::string opstr;
  switch (binop.op) {
    case ebpf::bpftrace::Parser::token::EQ:    opstr = "=="; break;
    case ebpf::bpftrace::Parser::token::NE:    opstr = "!="; break;
    case ebpf::bpftrace::Parser::token::LE:    opstr = "<="; break;
    case ebpf::bpftrace::Parser::token::GE:    opstr = ">="; break;
    case ebpf::bpftrace::Parser::token::LT:    opstr = "<"; break;
    case ebpf::bpftrace::Parser::token::GT:    opstr = ">"; break;
    case ebpf::bpftrace::Parser::token::LAND:  opstr = "&&"; break;
    case ebpf::bpftrace::Parser::token::LOR:   opstr = "||"; break;
    case ebpf::bpftrace::Parser::token::PLUS:  opstr = "+"; break;
    case ebpf::bpftrace::Parser::token::MINUS: opstr = "-"; break;
    case ebpf::bpftrace::Parser::token::MUL:   opstr = "*"; break;
    case ebpf::bpftrace::Parser::token::DIV:   opstr = "/"; break;
    case ebpf::bpftrace::Parser::token::MOD:   opstr = "%"; break;
    case ebpf::bpftrace::Parser::token::BAND:  opstr = "&"; break;
    case ebpf::bpftrace::Parser::token::BOR:   opstr = "|"; break;
    case ebpf::bpftrace::Parser::token::BXOR:  opstr = "^"; break;
    default: abort();
  }

  out_ << indent << opstr << std::endl;

  ++depth_;
  binop.left->accept(*this);
  binop.right->accept(*this);
  --depth_;
}

void Printer::visit(Unop &unop)
{
  std::string indent(depth_, ' ');
  std::string opstr;
  switch (unop.op) {
    case ebpf::bpftrace::Parser::token::LNOT: opstr = "!"; break;
    case ebpf::bpftrace::Parser::token::BNOT: opstr = "~"; break;
    default: abort();
  }

  out_ << indent << opstr << std::endl;

  ++depth_;
  unop.expr->accept(*this);
  --depth_;
}

void Printer::visit(ExprStatement &expr)
{
  ++depth_;
  expr.expr->accept(*this);
  --depth_;
}

void Printer::visit(AssignMapStatement &assignment)
{
  std::string indent(depth_, ' ');
  out_ << indent << "=" << std::endl;

  ++depth_;
  assignment.map->accept(*this);
  assignment.expr->accept(*this);
  --depth_;
}

void Printer::visit(AssignMapCallStatement &assignment)
{
  std::string indent(depth_, ' ');
  out_ << indent << "=" << std::endl;

  ++depth_;
  assignment.map->accept(*this);
  assignment.call->accept(*this);
  --depth_;
}

void Printer::visit(Predicate &pred)
{
  std::string indent(depth_, ' ');
  out_ << indent << "pred" << std::endl;

  ++depth_;
  pred.expr->accept(*this);
  --depth_;
}

void Printer::visit(Probe &probe)
{
  std::string indent(depth_, ' ');
  out_ << indent << probe.type << ":" << probe.attach_point << std::endl;

  ++depth_;
  if (probe.pred) {
    probe.pred->accept(*this);
  }
  for (Statement *stmt : *probe.stmts) {
    stmt->accept(*this);
  }
  --depth_;
}

void Printer::visit(Program &program)
{
  std::string indent(depth_, ' ');
  out_ << indent << "Program" << std::endl;

  ++depth_;
  for (Probe *probe : *program.probes) {
    probe->accept(*this);
  }
  --depth_;
}

} // namespace ast
} // namespace bpftrace
} // namespace ebpf
