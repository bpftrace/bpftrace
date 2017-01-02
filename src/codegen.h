#pragma once

#include "ast.h"
#include "map.h"

#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>

namespace ebpf {
namespace bpftrace {
namespace ast {

using namespace llvm;

class Codegen : public Visitor {
public:
  Codegen(Module &mod, LLVMContext &context) : context_(context),
                                               module_(mod),
                                               b_(context_)
                                               { }

  void visit(Integer &integer) override;
  void visit(Builtin &builtin) override;
  void visit(Call &call) override;
  void visit(Map &map) override;
  void visit(Binop &binop) override;
  void visit(Unop &unop) override;
  void visit(ExprStatement &expr) override;
  void visit(AssignMapStatement &assignment) override;
  void visit(AssignMapCallStatement &assignment) override;
  void visit(Predicate &pred) override;
  void visit(Probe &probe) override;
  void visit(Program &program) override;

private:
  LLVMContext &context_;
  Module &module_;
  IRBuilder<> b_;
  Value *expr_ = nullptr;
  std::map<std::string, std::unique_ptr<ebpf::bpftrace::Map>> maps_;
};

} // namespace ast
} // namespace bpftrace
} // namespace ebpf
