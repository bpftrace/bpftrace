#include "semantic_analyser.h"
#include "ast.h"
#include "parser.tab.hh"

namespace ebpf {
namespace bpftrace {
namespace ast {

void SemanticAnalyser::visit(Integer &integer)
{
}

void SemanticAnalyser::visit(Builtin &builtin)
{
}

void SemanticAnalyser::visit(Call &call)
{
  if (call.vargs) {
    for (Expression *expr : *call.vargs) {
      expr->accept(*this);
    }
  }
}

void SemanticAnalyser::visit(Map &map)
{
  if (map.vargs) {
    for (Expression *expr : *map.vargs) {
      expr->accept(*this);
    }
  }
}

void SemanticAnalyser::visit(Binop &binop)
{
  binop.left->accept(*this);
  switch (binop.op) {
    case ebpf::bpftrace::Parser::token::EQ:    break;
    case ebpf::bpftrace::Parser::token::NE:    break;
    case ebpf::bpftrace::Parser::token::LE:    break;
    case ebpf::bpftrace::Parser::token::GE:    break;
    case ebpf::bpftrace::Parser::token::LT:    break;
    case ebpf::bpftrace::Parser::token::GT:    break;
    case ebpf::bpftrace::Parser::token::LAND:  break;
    case ebpf::bpftrace::Parser::token::LOR:   break;
    case ebpf::bpftrace::Parser::token::PLUS:  break;
    case ebpf::bpftrace::Parser::token::MINUS: break;
    case ebpf::bpftrace::Parser::token::MUL:   break;
    case ebpf::bpftrace::Parser::token::DIV:   break;
    case ebpf::bpftrace::Parser::token::MOD:   break;
    case ebpf::bpftrace::Parser::token::BAND:  break;
    case ebpf::bpftrace::Parser::token::BOR:   break;
    case ebpf::bpftrace::Parser::token::BXOR:  break;
    default: break;
  }
  binop.right->accept(*this);
}

void SemanticAnalyser::visit(Unop &unop)
{
  switch (unop.op) {
    case ebpf::bpftrace::Parser::token::LNOT: break;
    case ebpf::bpftrace::Parser::token::BNOT: break;
    default: break;
  }
  unop.expr->accept(*this);
}

void SemanticAnalyser::visit(ExprStatement &expr)
{
  expr.expr->accept(*this);
}

void SemanticAnalyser::visit(AssignMapStatement &assignment)
{
  assignment.map->accept(*this);
  assignment.expr->accept(*this);
}

void SemanticAnalyser::visit(AssignMapCallStatement &assignment)
{
  assignment.map->accept(*this);
  assignment.call->accept(*this);
}

void SemanticAnalyser::visit(Predicate &pred)
{
  pred.expr->accept(*this);
}

void SemanticAnalyser::visit(Probe &probe)
{
  if (probe.pred) {
    probe.pred->accept(*this);
  }
  for (Statement *stmt : *probe.stmts) {
    stmt->accept(*this);
  }
}

void SemanticAnalyser::visit(Program &program)
{
  for (Probe *probe : *program.probes) {
    probe->accept(*this);
  }
}

int SemanticAnalyser::analyse()
{
  root_->accept(*this);
  return 0;
}

} // namespace ast
} // namespace bpftrace
} // namespace ebpf
