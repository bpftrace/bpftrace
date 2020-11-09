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
  explicit CodegenLLVM(Node *root, BPFtrace &bpftrace);

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
  void visit(Tuple &tuple) override;
  void visit(ExprStatement &expr) override;
  void visit(AssignMapStatement &assignment) override;
  void visit(AssignVarStatement &assignment) override;
  void visit(If &if_block) override;
  void visit(Unroll &unroll) override;
  void visit(While &while_block) override;
  void visit(Jump &jump) override;
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

  // Exists to make calling from a debugger easier
  void DumpIR(void);
  void DumpIR(std::ostream &out);
  void createFormatStringCall(Call &call, int &id, CallArgs &call_args,
                              const std::string &call_name, AsyncAction async_action);

  void createPrintMapCall(Call &call);
  void createPrintNonMapCall(Call &call, int &id);

  void generate_ir(void);
  void optimize(void);
  std::unique_ptr<BpfOrc> emit(void);
  void emit_elf(const std::string &filename);
  // Combine generate_ir, optimize and emit into one call
  std::unique_ptr<BpfOrc> compile(void);

private:
  class ScopedExprDeleter
  {
  public:
    explicit ScopedExprDeleter(std::function<void()> deleter)
    {
      deleter_ = std::move(deleter);
    }

    ~ScopedExprDeleter()
    {
      if (deleter_)
        deleter_();
    }

    std::function<void()> disarm()
    {
      auto ret = deleter_;
      deleter_ = nullptr;
      return ret;
    }

  private:
    std::function<void()> deleter_;
  };

  void generateProbe(Probe &probe,
                     const std::string &full_func_id,
                     const std::string &section_name,
                     FunctionType *func_type,
                     bool expansion);
  [[nodiscard]] ScopedExprDeleter accept(Node *node);

  void compareStructure(SizedType &our_type, llvm::Type *llvm_type);

  Function *createLog2Function();
  Function *createLinearFunction();

  void binop_string(Binop &binop);
  void binop_buf(Binop &binop);
  void binop_int(Binop &binop);

  void kstack_ustack(const std::string &ident,
                     StackType stack_type,
                     const location &loc);

  Node *root_;
  LLVMContext context_;
  std::unique_ptr<Module> module_;
  std::unique_ptr<ExecutionEngine> ee_;
  TargetMachine *TM_;
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
  // Used if there are duplicate USDT entries
  int current_usdt_location_index_{ 0 };

  std::map<std::string, AllocaInst *> variables_;
  int printf_id_ = 0;
  int time_id_ = 0;
  int cat_id_ = 0;
  int strftime_id_ = 0;
  uint64_t join_id_ = 0;
  int system_id_ = 0;
  int non_map_print_id_ = 0;

  Function *linear_func_ = nullptr;
  Function *log2_func_ = nullptr;
  std::unique_ptr<BpfOrc> orc_;

  size_t getStructSize(StructType *s)
  {
    return layout_.getTypeAllocSize(s);
  }

  std::vector<std::tuple<BasicBlock *, BasicBlock *>> loops_;

  enum class State
  {
    INIT,
    IR,
    OPT,
    DONE,
  };
  State state_ = State::INIT;
};

} // namespace ast
} // namespace bpftrace
