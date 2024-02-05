#pragma once

#include <functional>
#include <iostream>
#include <optional>
#include <ostream>
#include <tuple>

#include <llvm/ExecutionEngine/MCJIT.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/raw_os_ostream.h>

#include "ast/dibuilderbpf.h"
#include "ast/irbuilderbpf.h"
#include "ast/visitors.h"
#include "bpftrace.h"
#include "format_string.h"
#include "location.hh"
#include "map.h"
#include "required_resources.h"

namespace bpftrace {
namespace ast {

using namespace llvm;

using CallArgs = std::vector<std::tuple<FormatString, std::vector<Field>>>;

class CodegenLLVM : public Visitor {
public:
  explicit CodegenLLVM(Node *root, BPFtrace &bpftrace);

  void visit(Integer &integer) override;
  void visit(PositionalParameter &param) override;
  void visit(String &string) override;
  void visit(Identifier &identifier) override;
  void visit(Builtin &builtin) override;
  void visit(StackMode &) override{};
  void visit(Call &call) override;
  void visit(Sizeof &szof) override;
  void visit(Offsetof &ofof) override;
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
  int getNextIndexForProbe();
  Value *createLogicalAnd(Binop &binop);
  Value *createLogicalOr(Binop &binop);

  // Exists to make calling from a debugger easier
  void DumpIR(void);
  void DumpIR(std::ostream &out);
  void DumpIR(const std::string filename);
  void createFormatStringCall(Call &call,
                              int &id,
                              CallArgs &call_args,
                              const std::string &call_name,
                              AsyncAction async_action);

  void createPrintMapCall(Call &call);
  void createPrintNonMapCall(Call &call, int &id);

  void createMapDefinition(const std::string &name,
                           libbpf::bpf_map_type map_type,
                           uint64_t max_entries,
                           const MapKey &key,
                           const SizedType &value_type);

  void generate_ir(void);
  void generate_maps(const RequiredResources &resources);
  void optimize(void);
  bool verify(void);
  BpfBytecode emit(void);
  void emit_elf(const std::string &filename);
  void emit(raw_pwrite_stream &stream);
  // Combine generate_ir, optimize and emit into one call
  BpfBytecode compile(void);

private:
  static constexpr char LLVMTargetTriple[] = "bpf-pc-linux";
  class ScopedExprDeleter {
  public:
    explicit ScopedExprDeleter(std::function<void()> deleter)
    {
      deleter_ = std::move(deleter);
    }

    ScopedExprDeleter(const ScopedExprDeleter &other) = delete;
    ScopedExprDeleter &operator=(const ScopedExprDeleter &other) = delete;

    ScopedExprDeleter(ScopedExprDeleter &&other)
    {
      *this = std::move(other);
    }

    ScopedExprDeleter &operator=(ScopedExprDeleter &&other)
    {
      deleter_ = other.disarm();
      return *this;
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

  // Generate a probe for `current_attach_point_`
  //
  // If `dummy` is passed, then code is generated but immediately thrown away.
  // This is used to progress state (eg. asyncids) in this class instance for
  // invalid probes that still need to be visited.
  void generateProbe(Probe &probe,
                     const std::string &full_func_id,
                     const std::string &section_name,
                     FunctionType *func_type,
                     bool expansion,
                     std::optional<int> usdt_location_index = std::nullopt,
                     bool dummy = false);

  [[nodiscard]] ScopedExprDeleter accept(Node *node);
  [[nodiscard]] std::tuple<Value *, ScopedExprDeleter> getMapKey(Map &map);
  AllocaInst *getMultiMapKey(Map &map, const std::vector<Value *> &extra_keys);

  void compareStructure(SizedType &our_type, llvm::Type *llvm_type);

  Function *createLog2Function();
  Function *createLinearFunction();
  MDNode *createLoopMetadata();

  std::pair<Value *, uint64_t> getString(Expression *expr);

  void binop_string(Binop &binop);
  void binop_integer_array(Binop &binop);
  void binop_buf(Binop &binop);
  void binop_int(Binop &binop);
  void binop_ptr(Binop &binop);

  void unop_int(Unop &unop);
  void unop_ptr(Unop &unop);

  void kstack_ustack(const std::string &ident,
                     StackType stack_type,
                     const location &loc);

  int get_probe_id();

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
  void readDatastructElemFromStack(Value *src_data,
                                   Value *index,
                                   llvm::Type *data_type,
                                   const SizedType &elem_type,
                                   ScopedExprDeleter &scoped_del);
  void probereadDatastructElem(Value *src_data,
                               Value *offset,
                               const SizedType &data_type,
                               const SizedType &elem_type,
                               ScopedExprDeleter &scoped_del,
                               location loc,
                               const std::string &temp_name);

  void createIncDec(Unop &unop);

  Function *createMapLenCallback();

  // Return a lambda that has captured-by-value CodegenLLVM's async id state
  // (ie `printf_id_`, `mapped_printf_id_`, etc.).  Running the returned lambda
  // will restore `CodegenLLVM`s async id state back to when this function was
  // first called.
  std::function<void()> create_reset_ids();

  Node *root_ = nullptr;

  BPFtrace &bpftrace_;
  std::unique_ptr<LLVMContext> context_;
  std::unique_ptr<TargetMachine> target_machine_;
  std::unique_ptr<Module> module_;
  IRBuilderBPF b_;

  DIBuilderBPF debug_;

  const DataLayout &datalayout() const
  {
    return module_->getDataLayout();
  }

  Value *expr_ = nullptr;
  std::function<void()> expr_deleter_; // intentionally empty
  Value *ctx_;
  AttachPoint *current_attach_point_ = nullptr;
  std::string probefull_;
  std::string tracepoint_struct_;
  uint64_t probe_count_ = 0;
  // Probes and attach points are indexed from 1, 0 means no index
  // (no index is used for probes whose attach points are indexed individually)
  int next_probe_index_ = 1;
  // Used if there are duplicate USDT entries
  int current_usdt_location_index_{ 0 };

  std::map<std::string, AllocaInst *> variables_;
  int printf_id_ = 0;
  int mapped_printf_id_ = 0;
  int time_id_ = 0;
  int cat_id_ = 0;
  int strftime_id_ = 0;
  uint64_t join_id_ = 0;
  int system_id_ = 0;
  int non_map_print_id_ = 0;
  uint64_t watchpoint_id_ = 0;
  int cgroup_path_id_ = 0;
  int skb_output_id_ = 0;

  Function *linear_func_ = nullptr;
  Function *log2_func_ = nullptr;
  MDNode *loop_metadata_ = nullptr;

  size_t getStructSize(StructType *s)
  {
    return module_->getDataLayout().getTypeAllocSize(s);
  }

  std::vector<std::tuple<BasicBlock *, BasicBlock *>> loops_;
  std::unordered_map<std::string, bool> probe_names_;

  enum class State {
    INIT,
    IR,
    OPT,
    DONE,
  };
  State state_ = State::INIT;
};

} // namespace ast
} // namespace bpftrace
