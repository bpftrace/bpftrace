#include "codegen.h"
#include "ast.h"
#include "parser.tab.hh"

namespace ebpf {
namespace bpftrace {
namespace ast {

void Codegen::visit(Integer &integer)
{
  expr_ = ConstantInt::get(module_.getContext(), APInt(64, integer.n)); // TODO fix bit width
}

void Codegen::visit(Variable &var)
{
}

void Codegen::visit(Binop &binop)
{
}

void Codegen::visit(Unop &unop)
{
  switch (unop.op) {
    case ebpf::bpftrace::Parser::token::LNOT: expr_ = b_.CreateNot(expr_); break;
    case ebpf::bpftrace::Parser::token::BNOT: expr_ = b_.CreateNeg(expr_); break;
    default: break;
  }
}

void Codegen::visit(ExprStatement &expr)
{
}

void Codegen::visit(AssignStatement &assignment)
{
}

void Codegen::visit(Predicate &pred)
{
}

void Codegen::visit(Probe &probe)
{
}

void Codegen::visit(Program &program)
{
}

} // namespace ast
} // namespace bpftrace
} // namespace ebpf
