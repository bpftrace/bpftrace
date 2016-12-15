#include "ast.h"

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
  if (vargs != nullptr) {
    for (Expression *expr : *vargs) {
      expr->print_ast(out, depth+1);
    }
  }
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
  out << indent << "Probe" << std::endl;
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
