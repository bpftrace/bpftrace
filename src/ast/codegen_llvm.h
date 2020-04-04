#pragma once

#include <iostream>
#include <ostream>

#include "ast.h"
#include "bpftrace.h"
#include "irbuilderbpf.h"
#include "map.h"

#include <llvm/Support/raw_os_ostream.h>
#include <llvm/ExecutionEngine/MCJIT.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>

namespace bpftrace {
namespace ast {

using namespace llvm;

using CallArgs = std::vector<std::tuple<std::string, std::vector<Field>>>;

class CodegenLLVM : public Visitor {
public:
  explicit CodegenLLVM(Node *root, BPFtrace &bpftrace) :
    root_(root),
    module_(std::make_unique<Module>("bpftrace", context_)),
    b_(context_, *module_.get(), bpftrace),
    layout_(module_.get()),
    bpftrace_(bpftrace)
    { }

  void visit(Integer &integer) override;
  void visit(PositionalParameter &param) override;
  void visit(String &string) override;
  void visit(Identifier &identifier) override;
  void visit(Builtin &builtin) override;
  void visit(StackMode &) override { };
  void visit(Call &call) override;
  void visit(Map &map) override;
  void visit(Variable &var) override;
  void visit(Binop &binop) override;
  void visit(Unop &unop) override;
  void visit(Ternary &ternary) override;
  void visit(FieldAccess &acc) override;
  void visit(ArrayAccess &arr) override;
  void visit(Cast &cast) override;
  void visit(ExprStatement &expr) override;
  void visit(AssignMapStatement &assignment) override;
  void visit(AssignVarStatement &assignment) override;
  void visit(If &if_block) override;
  void visit(Unroll &unroll) override;
  void visit(Predicate &pred) override;
  void visit(AttachPoint &ap) override;
  void visit(Probe &probe) override;
  void visit(Program &program) override;
  AllocaInst *getMapKey(Map &map);
  AllocaInst *getHistMapKey(Map &map, Value *log2);
  int         getNextIndexForProbe(const std::string &probe_name);
  std::string getSectionNameForProbe(const std::string &probe_name, int index);
  Value      *createLogicalAnd(Binop &binop);
  Value      *createLogicalOr(Binop &binop);

  void DumpIR();
  void DumpIR(llvm::raw_os_ostream &out);
  void createLog2Function();
  void createLinearFunction();
  void createFormatStringCall(Call &call, int &id, CallArgs &call_args,
                              const std::string &call_name, AsyncAction async_action);
  std::unique_ptr<BpfOrc> compile(DebugLevel debug=DebugLevel::kNone, std::ostream &out=std::cout);

private:
  Node *root_;
  LLVMContext context_;
  std::unique_ptr<Module> module_;
  std::unique_ptr<ExecutionEngine> ee_;
  IRBuilderBPF b_;
  DataLayout layout_;
  Value *expr_ = nullptr;
  std::function<void()> expr_deleter_; // intentionally empty
  Value *ctx_;
  AttachPoint *current_attach_point_ = nullptr;
  BPFtrace &bpftrace_;
  std::string probefull_;
  std::string tracepoint_struct_;
  std::map<std::string, int> next_probe_index_;

  std::map<std::string, AllocaInst *> variables_;
  int printf_id_ = 0;
  int time_id_ = 0;
  int cat_id_ = 0;
  uint64_t join_id_ = 0;
  int system_id_ = 0;

  size_t getStructSize(StructType *s)
  {
    return layout_.getTypeAllocSize(s);
  }
};

} // namespace ast
} // namespace bpftrace
