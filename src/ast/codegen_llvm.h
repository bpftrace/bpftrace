#pragma once

#include <iostream>
#include <optional>
#include <ostream>
#include <tuple>

#include "bpftrace.h"
#include "irbuilderbpf.h"
#include "location.hh"
#include "map.h"
#include "visitors.h"

#include <llvm/Support/raw_os_ostream.h>
#include <llvm/ExecutionEngine/MCJIT.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>

namespace bpftrace {
namespace ast {

using namespace llvm;

using CallArgs = std::vector<std::tuple<std::string, std::vector<Field>>>;

class CodegenLLVM : public Visitor
{
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
  AllocaInst *getHistMapKey(Map &map, Value *log2);
  int         getNextIndexForProbe(const std::string &probe_name);
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

    ScopedExprDeleter(const ScopedExprDeleter &other) = delete;
    ScopedExprDeleter &operator=(const ScopedExprDeleter &other) = delete;
    ScopedExprDeleter(ScopedExprDeleter &&other) = default;
    ScopedExprDeleter &operator=(ScopedExprDeleter &&other) = default;

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
                     bool expansion,
                     std::optional<int> usdt_location_index = std::nullopt);

  [[nodiscard]] ScopedExprDeleter accept(Node *node);
  [[nodiscard]] std::tuple<Value *, ScopedExprDeleter> getMapKey(Map &map);

  void compareStructure(SizedType &our_type, llvm::Type *llvm_type);

  Function *createLog2Function();
  Function *createLinearFunction();

  void binop_string(Binop &binop);
  void binop_buf(Binop &binop);
  void binop_int(Binop &binop);
  void kstack_ustack(const std::string &ident,
                     StackType stack_type,
                     const location &loc);

  // Create return instruction
  //
  // If null, return value will depend on current attach point
  void createRet(Value *value = nullptr);

  // Every time we see a watchpoint that specifies a function + arg pair, we
  // generate a special "setup" probe that:
  //
  // * sends SIGSTOP to the tracee
  // * pulls out the function arg
  // * sends an asyncaction to the bpftrace runtime and specifies the arg value
  //   and which of the "real" probes to attach to the addr in the arg
  //
  // We need a separate "setup" probe per probe because we hard code the index
  // of the "real" probe the setup probe is to be replaced by.
  void generateWatchpointSetupProbe(FunctionType *func_type,
                                    const std::string &expanded_probe_name,
                                    int arg_num,
                                    int index);

  void readDatastructElemFromStack(Value *src_data,
                                   Value *index,
                                   const SizedType &data_type,
                                   const SizedType &elem_type,
                                   ScopedExprDeleter &scoped_del);
  void probereadDatastructElem(Value *src_data,
                               Value *offset,
                               const SizedType &data_type,
                               const SizedType &elem_type,
                               ScopedExprDeleter &scoped_del,
                               location loc,
                               const std::string &temp_name);

  Node *root_ = nullptr;

  BPFtrace &bpftrace_;
  std::unique_ptr<BpfOrc> orc_;
  std::unique_ptr<Module> module_;
  IRBuilderBPF b_;

  const DataLayout &datalayout() const
  {
    return orc_->getDataLayout();
  }

  Value *expr_ = nullptr;
  std::function<void()> expr_deleter_; // intentionally empty
  Value *ctx_;
  AttachPoint *current_attach_point_ = nullptr;
  std::string probefull_;
  std::string tracepoint_struct_;
  std::map<std::string, int> next_probe_index_;
  // Used if there are duplicate USDT entries
  int current_usdt_location_index_{ 0 };

  std::map<std::string, AllocaInst *> variables_;
  int printf_id_ = 0;
  int seq_printf_id_ = 0;
  int time_id_ = 0;
  int cat_id_ = 0;
  int strftime_id_ = 0;
  uint64_t join_id_ = 0;
  int system_id_ = 0;
  int non_map_print_id_ = 0;
  uint64_t watchpoint_id_ = 0;

  Function *linear_func_ = nullptr;
  Function *log2_func_ = nullptr;

  size_t getStructSize(StructType *s)
  {
    return datalayout().getTypeAllocSize(s);
  }

  std::vector<std::tuple<BasicBlock *, BasicBlock *>> loops_;
  std::unordered_map<std::string, bool> probe_names_;

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
