#include "codegen_bcc.h"
#include "ast.h"
#include "parser.tab.hh"

namespace ebpf {
namespace bpftrace {
namespace ast {

void CodegenBCC::visit(Integer &integer)
{
  code << integer.n;
}

void CodegenBCC::visit(Builtin &builtin)
{
  code << builtin.ident;
}

void CodegenBCC::visit(Call &call)
{
  code << call.func << "(";
  if (call.vargs) {
    for (Expression *expr : *call.vargs) {
      expr->accept(*this);
      code << ", ";
    }
  }
  code << ")";
}

void CodegenBCC::visit(Map &map)
{
  code << map.ident;
  if (map.vargs) {
    code << "[";
    for (Expression *expr : *map.vargs) {
      expr->accept(*this);
      code << ", ";
    }
    code << "]";
  }
}

void CodegenBCC::visit(Binop &binop)
{
  code << "(";
  binop.left->accept(*this);
  switch (binop.op) {
    case ebpf::bpftrace::Parser::token::EQ:    code << "=="; break;
    case ebpf::bpftrace::Parser::token::NE:    code << "!="; break;
    case ebpf::bpftrace::Parser::token::LE:    code << "<="; break;
    case ebpf::bpftrace::Parser::token::GE:    code << ">="; break;
    case ebpf::bpftrace::Parser::token::LT:    code << "<";  break;
    case ebpf::bpftrace::Parser::token::GT:    code << ">";  break;
    case ebpf::bpftrace::Parser::token::LAND:  code << "&&"; break;
    case ebpf::bpftrace::Parser::token::LOR:   code << "||"; break;
    case ebpf::bpftrace::Parser::token::PLUS:  code << "+";  break;
    case ebpf::bpftrace::Parser::token::MINUS: code << "-";  break;
    case ebpf::bpftrace::Parser::token::MUL:   code << "*";  break;
    case ebpf::bpftrace::Parser::token::DIV:   code << "/";  break;
    case ebpf::bpftrace::Parser::token::MOD:   code << "%";  break;
    case ebpf::bpftrace::Parser::token::BAND:  code << "&";  break;
    case ebpf::bpftrace::Parser::token::BOR:   code << "|";  break;
    case ebpf::bpftrace::Parser::token::BXOR:  code << "^";  break;
    default: break;
  }
  binop.right->accept(*this);
  code << ")";
}

void CodegenBCC::visit(Unop &unop)
{
  code << "(";
  switch (unop.op) {
    case ebpf::bpftrace::Parser::token::LNOT: code << "!"; break;
    case ebpf::bpftrace::Parser::token::BNOT: code << "~"; break;
    default: break;
  }
  unop.expr->accept(*this);
  code << ")";
}

void CodegenBCC::visit(ExprStatement &expr)
{
  expr.expr->accept(*this);
}

void CodegenBCC::visit(AssignMapStatement &assignment)
{
  assignment.map->accept(*this);
  code << "=";
  assignment.expr->accept(*this);
}

void CodegenBCC::visit(AssignMapCallStatement &assignment)
{
  assignment.map->accept(*this);
  code << "=";
  assignment.call->accept(*this);
}

void CodegenBCC::visit(Predicate &pred)
{
  code << "if (!(";
  pred.expr->accept(*this);
  code << ")) return 0;" << std::endl;
}

void CodegenBCC::visit(Probe &probe)
{
  code << "int " << probe.type << "__" << probe.attach_point << "() {" << std::endl;

  if (probe.pred) {
    probe.pred->accept(*this);
  }
  for (Statement *stmt : *probe.stmts) {
    stmt->accept(*this);
    code << ";" << std::endl;
  }

  code << "return 0;\n}" << std::endl;
}

void CodegenBCC::visit(Program &program)
{
  for (Probe *probe : *program.probes) {
    probe->accept(*this);
  }
}

} // namespace ast
} // namespace bpftrace
} // namespace ebpf
