#pragma once

#include "ast.h"

#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>

namespace ebpf {
namespace bpftrace {
namespace ast {

using namespace llvm;

class Codegen : public Visitor {
public:
  Codegen() : b_(context_),
              module_("bpftrace", context_)
              { }

  void visit(Integer &integer) override;
  void visit(Variable &var) override;
  void visit(Binop &binop) override;
  void visit(Unop &unop) override;
  void visit(ExprStatement &expr) override;
  void visit(AssignStatement &assignment) override;
  void visit(Predicate &pred) override;
  void visit(Probe &probe) override;
  void visit(Program &program) override;

//private:
  LLVMContext context_;
  IRBuilder<> b_;
  Module module_;
  Value *expr_ = nullptr;
};

} // namespace ast
} // namespace bpftrace
} // namespace ebpf
