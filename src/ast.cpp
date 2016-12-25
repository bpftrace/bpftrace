#include "ast.h"

namespace ebpf {
namespace bpftrace {
namespace ast {

void Integer::accept(Visitor &v) {
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

void AssignStatement::accept(Visitor &v) {
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

} // namespace ast
} // namespace bpftrace
} // namespace ebpf
