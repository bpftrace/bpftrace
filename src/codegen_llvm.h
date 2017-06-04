#pragma once

#include "ast.h"
#include "bpftrace.h"
#include "irbuilderbpf.h"
#include "map.h"

#include <llvm/ExecutionEngine/MCJIT.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>

namespace bpftrace {
namespace ast {

using namespace llvm;

class CodegenLLVM : public Visitor {
public:
  explicit CodegenLLVM(Node *root, BPFtrace &bpftrace) :
    root_(root),
    module_(std::make_unique<Module>("bpftrace", context_)),
    b_(context_, *module_.get(), bpftrace),
    bpftrace_(bpftrace)
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
  AllocaInst *getMapKey(Map &map);
  AllocaInst *getQuantizeMapKey(Map &map, Value *log2);

  void createLog2Function();
  int compile(bool debug=false);

private:
  Node *root_;
  LLVMContext context_;
  std::unique_ptr<Module> module_;
  std::unique_ptr<ExecutionEngine> ee_;
  IRBuilderBPF b_;
  Value *expr_ = nullptr;
  BPFtrace &bpftrace_;
};

} // namespace ast
} // namespace bpftrace
