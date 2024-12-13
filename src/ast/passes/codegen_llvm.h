#pragma once

#include <functional>
#include <iostream>
#include <optional>
#include <ostream>
#include <tuple>

#include <llvm/ADT/FunctionExtras.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/raw_os_ostream.h>
#include <llvm/Target/TargetMachine.h>

#include "ast/async_ids.h"
#include "ast/dibuilderbpf.h"
#include "ast/irbuilderbpf.h"
#include "ast/visitor.h"
#include "bpftrace.h"
#include "codegen_resources.h"
#include "format_string.h"
#include "kfuncs.h"
#include "location.hh"
#include "required_resources.h"

namespace bpftrace {
namespace ast {

using namespace llvm;

using CallArgs = std::vector<std::tuple<FormatString, std::vector<Field>>>;

struct VariableLLVM {
  llvm::Value *value;
  llvm::Type *type;
};

// ScopedExpr ties an SSA value to a "delete" function, that typically will end
// the lifetime of some needed storage. You must explicitly construct a
// ScopedExpr from either:
// * A value only, with no associated function when out of scope.
// * A value and associated function to run when out of scope.
// * A value and another ScopedExpr, whose lifetime will be preserved until
//   this value is out of scope.
class ScopedExpr {
public:
  // Neither a value nor a deletion method.
  explicit ScopedExpr()
  {
  }

  // Value only.
  explicit ScopedExpr(Value *value) : value_(value)
  {
  }

  // Value with an explicit deletion method.
  explicit ScopedExpr(Value *value, llvm::unique_function<void()> &&deleter)
      : value_(value), deleter_(std::move(deleter))
  {
  }

  // Value with another ScopedExpr whose lifetime should be bound.
  explicit ScopedExpr(Value *value, ScopedExpr &&other) : value_(value)
  {
    deleter_.swap(other.deleter_);
  }

  ScopedExpr(ScopedExpr &&other) : value_(other.value_)
  {
    deleter_.swap(other.deleter_);
  }

  ScopedExpr &operator=(ScopedExpr &&other)
  {
    value_ = other.value_;
    deleter_.swap(other.deleter_);
    return *this;
  }

  ScopedExpr(const ScopedExpr &other) = delete;
  ScopedExpr &operator=(const ScopedExpr &other) = delete;

  ~ScopedExpr()
  {
    if (deleter_) {
      deleter_.value()();
      deleter_.reset();
    }
  }

  Value *value()
  {
    return value_;
  }

  // May be used to disable the deletion method, essentially leaking some
  // memory within the frame. The use of this function should be generally
  // considered a bug, as it will make dealing with larger functions and
  // multiple scopes more problematic over time.
  void disarm()
  {
    deleter_.reset();
  }

private:
  Value *value_ = nullptr;
  std::optional<llvm::unique_function<void()>> deleter_;
};

class CodegenLLVM : public Visitor<CodegenLLVM, ScopedExpr> {
public:
  explicit CodegenLLVM(ASTContext &ctx, BPFtrace &bpftrace);
  explicit CodegenLLVM(ASTContext &ctx,
                       BPFtrace &bpftrace,
                       std::unique_ptr<USDTHelper> usdt_helper);

  using Visitor<CodegenLLVM, ScopedExpr>::visit;
  ScopedExpr visit(Integer &integer);
  ScopedExpr visit(PositionalParameter &param);
  ScopedExpr visit(String &string);
  ScopedExpr visit(Identifier &identifier);
  ScopedExpr visit(Builtin &builtin);
  ScopedExpr visit(Call &call);
  ScopedExpr visit(Sizeof &szof);
  ScopedExpr visit(Offsetof &offof);
  ScopedExpr visit(Map &map);
  ScopedExpr visit(Variable &var);
  ScopedExpr visit(Binop &binop);
  ScopedExpr visit(Unop &unop);
  ScopedExpr visit(Ternary &ternary);
  ScopedExpr visit(FieldAccess &acc);
  ScopedExpr visit(ArrayAccess &arr);
  ScopedExpr visit(Cast &cast);
  ScopedExpr visit(Tuple &tuple);
  ScopedExpr visit(ExprStatement &expr);
  ScopedExpr visit(AssignMapStatement &assignment);
  ScopedExpr visit(AssignVarStatement &assignment);
  ScopedExpr visit(VarDeclStatement &decl);
  ScopedExpr visit(If &if_node);
  ScopedExpr visit(Unroll &unroll);
  ScopedExpr visit(While &while_block);
  ScopedExpr visit(For &f);
  ScopedExpr visit(Jump &jump);
  ScopedExpr visit(Predicate &pred);
  ScopedExpr visit(AttachPoint &ap);
  ScopedExpr visit(Probe &probe);
  ScopedExpr visit(Subprog &subprog);
  ScopedExpr visit(Program &program);
  ScopedExpr visit(Block &block);

  ScopedExpr getHistMapKey(Map &map, Value *log2, const location &loc);
  int getNextIndexForProbe();
  ScopedExpr createLogicalAnd(Binop &binop);
  ScopedExpr createLogicalOr(Binop &binop);

  // Exists to make calling from a debugger easier
  void DumpIR(void);
  void DumpIR(std::ostream &out);
  void DumpIR(const std::string filename);
  void createFormatStringCall(Call &call,
                              int id,
                              const CallArgs &call_args,
                              const std::string &call_name,
                              AsyncAction async_action);

  void createPrintMapCall(Call &call);
  void createPrintNonMapCall(Call &call, int id);

  void createMapDefinition(const std::string &name,
                           libbpf::bpf_map_type map_type,
                           uint64_t max_entries,
                           const SizedType &key_type,
                           const SizedType &value_type);
  Value *createTuple(
      const SizedType &tuple_type,
      const std::vector<std::pair<llvm::Value *, const location *>> &vals,
      const std::string &name,
      const location &loc);
  void createTupleCopy(const SizedType &expr_type,
                       const SizedType &var_type,
                       Value *dst_val,
                       Value *src_val);

  void generate_ir(void);
  libbpf::bpf_map_type get_map_type(const SizedType &val_type,
                                    const SizedType &key_type);
  bool is_array_map(const SizedType &val_type, const SizedType &key_type);
  bool map_has_single_elem(const SizedType &val_type,
                           const SizedType &key_type);
  void generate_maps(const RequiredResources &rr, const CodegenResources &cr);
  void generate_global_vars(const RequiredResources &resources,
                            const ::bpftrace::Config &bpftrace_config);
  void optimize(void);
  bool verify(void);
  BpfBytecode emit(bool disassemble);
  void emit_elf(const std::string &filename);
  void emit(raw_pwrite_stream &stream);
  // Combine generate_ir, optimize and emit into one call
  BpfBytecode compile(void);

private:
  static constexpr char LLVMTargetTriple[] = "bpf-pc-linux";

  // Generate a probe for `current_attach_point_`
  //
  // If `dummy` is passed, then code is generated but immediately thrown away.
  // This is used to progress state (eg. asyncids) in this class instance for
  // invalid probes that still need to be visited.
  void generateProbe(Probe &probe,
                     const std::string &full_func_id,
                     const std::string &name,
                     FunctionType *func_type,
                     std::optional<int> usdt_location_index = std::nullopt,
                     bool dummy = false);

  // Generate a probe and register it to the BPFtrace class.
  void add_probe(AttachPoint &ap,
                 Probe &probe,
                 const std::string &name,
                 FunctionType *func_type);

  [[nodiscard]] ScopedExpr getMapKey(Map &map);
  [[nodiscard]] ScopedExpr getMapKey(Map &map, Expression *key_expr);
  [[nodiscard]] ScopedExpr getMultiMapKey(
      Map &map,
      const std::vector<Value *> &extra_keys,
      const location &loc);

  void compareStructure(SizedType &our_type, llvm::Type *llvm_type);

  llvm::Function *createLog2Function();
  llvm::Function *createLinearFunction();
  MDNode *createLoopMetadata();

  std::pair<ScopedExpr, uint64_t> getString(Expression &expr);

  ScopedExpr binop_string(Binop &binop);
  ScopedExpr binop_integer_array(Binop &binop);
  ScopedExpr binop_buf(Binop &binop);
  ScopedExpr binop_int(Binop &binop);
  ScopedExpr binop_ptr(Binop &binop);

  ScopedExpr unop_int(Unop &unop);
  ScopedExpr unop_ptr(Unop &unop);

  ScopedExpr kstack_ustack(const std::string &ident,
                           StackType stack_type,
                           const location &loc);

  int get_probe_id();

  // Create return instruction
  //
  // If null, return value will depend on current attach point (void in subprog)
  void createRet(Value *value = nullptr);
  int getReturnValueForProbe(ProbeType probe_type);

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

  ScopedExpr readDatastructElemFromStack(ScopedExpr &&scoped_src,
                                         Value *index,
                                         const SizedType &data_type,
                                         const SizedType &elem_type);
  ScopedExpr readDatastructElemFromStack(ScopedExpr &&scoped_src,
                                         Value *index,
                                         llvm::Type *data_type,
                                         const SizedType &elem_type);
  ScopedExpr probereadDatastructElem(ScopedExpr &&scoped_src,
                                     Value *offset,
                                     const SizedType &data_type,
                                     const SizedType &elem_type,
                                     location loc,
                                     const std::string &temp_name);

  ScopedExpr createIncDec(Unop &unop);

  llvm::Function *createMapLenCallback();
  llvm::Function *createForEachMapCallback(For &f, llvm::Type *ctx_t);
  llvm::Function *createMurmurHash2Func();

  Value *createFmtString(int print_id);

  bool canAggPerCpuMapElems(const SizedType &val_type,
                            const SizedType &key_type);

  void maybeAllocVariable(const std::string &var_ident,
                          const SizedType &var_type,
                          const location &loc);
  VariableLLVM *maybeGetVariable(const std::string &);
  VariableLLVM &getVariable(const std::string &);

  llvm::Function *DeclareKernelFunc(Kfunc kfunc);

  CallInst *CreateKernelFuncCall(Kfunc kfunc,
                                 ArrayRef<Value *> args,
                                 const Twine &name);

  GlobalVariable *DeclareKernelVar(const std::string &name);

  BPFtrace &bpftrace_;
  std::unique_ptr<USDTHelper> usdt_helper_;
  std::unique_ptr<LLVMContext> context_;
  std::unique_ptr<TargetMachine> target_machine_;
  std::unique_ptr<Module> module_;
  AsyncIds async_ids_;
  IRBuilderBPF b_;

  DIBuilderBPF debug_;

  const DataLayout &datalayout() const
  {
    return module_->getDataLayout();
  }

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
  bool inside_subprog_ = false;

  std::vector<Node *> scope_stack_;
  std::unordered_map<Node *, std::map<std::string, VariableLLVM>> variables_;

  std::unordered_map<std::string, libbpf::bpf_map_type> map_types_;

  llvm::Function *linear_func_ = nullptr;
  llvm::Function *log2_func_ = nullptr;
  llvm::Function *murmur_hash_2_func_ = nullptr;
  llvm::Function *map_len_func_ = nullptr;
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
