#pragma once

#include <functional>
#include <iostream>
#include <optional>
#include <ostream>
#include <tuple>

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

class CodegenLLVM : public Visitor<CodegenLLVM> {
public:
  explicit CodegenLLVM(ASTContext &ctx, BPFtrace &bpftrace);
  explicit CodegenLLVM(ASTContext &ctx,
                       BPFtrace &bpftrace,
                       std::unique_ptr<USDTHelper> usdt_helper);

  using Visitor<CodegenLLVM>::visit;
  void visit(Integer &integer);
  void visit(Import &imp);
  void visit(PositionalParameter &param);
  void visit(String &string);
  void visit(Identifier &identifier);
  void visit(Builtin &builtin);
  void visit(Call &call);
  void visit(Sizeof &szof);
  void visit(Offsetof &offof);
  void visit(Map &map);
  void visit(Variable &var);
  void visit(Binop &binop);
  void visit(Unop &unop);
  void visit(Ternary &ternary);
  void visit(FieldAccess &acc);
  void visit(ArrayAccess &arr);
  void visit(Cast &cast);
  void visit(Tuple &tuple);
  void visit(ExprStatement &expr);
  void visit(AssignMapStatement &assignment);
  void visit(AssignVarStatement &assignment);
  void visit(VarDeclStatement &decl);
  void visit(If &if_node);
  void visit(Unroll &unroll);
  void visit(While &while_block);
  void visit(For &f);
  void visit(Jump &jump);
  void visit(Predicate &pred);
  void visit(AttachPoint &ap);
  void visit(Probe &probe);
  void visit(Subprog &subprog);
  void visit(Block &block);

  Value *getHistMapKey(Map &map, Value *log2, const location &loc);
  int getNextIndexForProbe();
  Value *createLogicalAnd(Binop &binop);
  Value *createLogicalOr(Binop &binop);

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
                           const SizedType &value_type,
                           bool external = false);
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

  // LinkTarget is a RAII-style class wrapping a descriptor. This is used
  // simply to collect all the linker FDs during the regular visit, which are
  // used at the end of code genereration.
  class LinkTarget {
  public:
    // Returns either an error or a LinkTarget, depending if the file was
    // opened successfully.
    static std::variant<std::string, LinkTarget> open(std::filesystem::path &name);
    ~LinkTarget() { if (fd_ >= 0) { close(fd_); } }
    LinkTarget(LinkTarget &&other) : name_(other.name_), fd_(other.fd_) {
      other.fd_ = -1; // Don't close on release.
    }
    int fd() const { return fd_; }
  private:
    LinkTarget(std::filesystem::path &name, int fd) : name_(name), fd_(fd) {}
    std::filesystem::path name_;
    int fd_;
  };

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

  [[nodiscard]] ScopedExprDeleter accept(Node *node);
  [[nodiscard]] std::tuple<Value *, ScopedExprDeleter> getMapKey(Map &map);
  [[nodiscard]] std::tuple<Value *, ScopedExprDeleter> getMapKey(
      Map &map,
      Expression *key_expr);
  Value *getMultiMapKey(Map &map,
                        const std::vector<Value *> &extra_keys,
                        const location &loc);

  void compareStructure(SizedType &our_type, llvm::Type *llvm_type);

  llvm::Function *createLog2Function();
  llvm::Function *createLinearFunction();
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

  llvm::Function *createMapLenCallback();
  llvm::Function *createForEachMapCallback(const For &f, llvm::Type *ctx_t);
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

  template <typename T>
  ScopedExprDeleter accept(T *node)
  {
    // This wraps the visit by essentially stacking return values in this
    // object, and popping them. This should be converted in the future to
    // using the structured visit (e.g. Visitor<CodegenLLVM, SomeThing>. The
    // special handling of Expression and Statement will also be removed once
    // we are no longer relying on RTTI for object type information.
    visit(node);
    auto deleter = std::move(expr_deleter_);
    expr_deleter_ = nullptr;
    return ScopedExprDeleter(deleter);
  }

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
  std::vector<LinkTarget> link_targets_;

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
