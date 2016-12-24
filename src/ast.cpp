#include "ast.h"

namespace ebpf {
namespace bpftrace {
namespace ast {

void Integer::accept(Visitor &v) {
  v.visit(*this);
}

void Variable::accept(Visitor &v) {
  v.visit(*this);
  ++v.depth_;
  if (vargs) {
    for (Expression *expr : *vargs) {
      expr->accept(v);
    }
  }
  --v.depth_;
}

void Binop::accept(Visitor &v) {
  v.visit(*this);
  ++v.depth_;
  left->accept(v);
  right->accept(v);
  --v.depth_;
}

void Unop::accept(Visitor &v) {
  v.visit(*this);
  ++v.depth_;
  expr->accept(v);
  --v.depth_;
}

void ExprStatement::accept(Visitor &v) {
  v.visit(*this);
  ++v.depth_;
  expr->accept(v);
  --v.depth_;
}

void AssignStatement::accept(Visitor &v) {
  v.visit(*this);
  ++v.depth_;
  var->accept(v);
  expr->accept(v);
  --v.depth_;
}

void Probe::accept(Visitor &v) {
  v.visit(*this);
  ++v.depth_;
  if (pred) {
    pred->accept(v);
  }
  for (Statement *stmt : *stmts) {
    stmt->accept(v);
  }
  --v.depth_;
}

void Program::accept(Visitor &v) {
  v.visit(*this);
  ++v.depth_;
  for (Probe *probe : *probes) {
    probe->accept(v);
  }
  --v.depth_;
}

} // namespace ast
} // namespace bpftrace
} // namespace ebpf
