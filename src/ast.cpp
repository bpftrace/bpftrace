#include "ast.h"

namespace ebpf {
namespace bpftrace {
namespace ast {

void Integer::print_ast(std::ostream &out, unsigned int depth) const
{
  out << "int: " << n << std::endl;
}

void Identifier::print_ast(std::ostream &out, unsigned int depth) const
{
  out << "ident: " << ident << std::endl;
}

void Statement::print_ast(std::ostream &out, unsigned int depth) const
{
  out << "stmt" << std::endl;
  out << std::string(depth, ' ');
  expr->print_ast(out, depth+1);
}

void Probe::print_ast(std::ostream &out, unsigned int depth) const
{
  out << "Probe" << std::endl;
  for (Statement *stmt : *stmts) {
    out << std::string(depth, ' ');
    stmt->print_ast(out, depth+1);
  }
}

void Program::print_ast(std::ostream &out, unsigned int depth) const
{
  out << "Program" << std::endl;
  ++depth;
  for (Probe *probe : *probes) {
    out << std::string(depth, ' ');
    probe->print_ast(out, depth+1);
  }
}

} // namespace ast
} // namespace bpftrace
} // namespace ebpf
