#pragma once

#include <bcc/bcc_usdt.h>
#include <llvm/Config/llvm-config.h>
#include <llvm/IR/IRBuilder.h>
#include <optional>

#include "ast/ast.h"
#include "ast/async_ids.h"
#include "bpftrace.h"
#include "types.h"

#define CREATE_ATOMIC_RMW(op, ptr, val, align, order)                          \
  CreateAtomicRMW((op), (ptr), (val), MaybeAlign((align)), (order))

namespace bpftrace::ast {

using namespace llvm;

class IRBuilderBPF : public IRBuilder<> {
public:
  IRBuilderBPF(LLVMContext &context,
               Module &module,
               BPFtrace &bpftrace,
               AsyncIds &async_ids);

  AllocaInst *CreateAllocaBPF(llvm::Type *ty, const std::string &name = "");
  AllocaInst *CreateAllocaBPF(const SizedType &stype,
                              const std::string &name = "");
  AllocaInst *CreateAllocaBPFInit(const SizedType &stype,
                                  const std::string &name);
  AllocaInst *CreateAllocaBPF(int bytes, const std::string &name = "");
  void CreateMemsetBPF(Value *ptr, Value *val, uint32_t size);
  void CreateMemcpyBPF(Value *dst, Value *src, uint32_t size);
  llvm::Type *GetType(const SizedType &stype);
  llvm::Type *GetMapValueType(const SizedType &stype);
  llvm::ConstantInt *GetIntSameSize(uint64_t C, llvm::Value *expr);
  llvm::ConstantInt *GetIntSameSize(uint64_t C, llvm::Type *ty);
  Value *GetMapVar(const std::string &map_name);
  Value *GetNull();
  CallInst *CreateMapLookup(Map &map,
                            Value *key,
                            const std::string &name = "lookup_elem");
  Value *CreateMapLookupElem(Map &map, Value *key, const Location &loc);
  Value *CreateMapLookupElem(const std::string &map_name,
                             Value *key,
                             SizedType &type,
                             const Location &loc);
  Value *CreatePerCpuMapAggElems(Map &map,
                                 Value *key,
                                 const SizedType &type,
                                 const Location &loc);
  void CreateMapUpdateElem(const std::string &map_ident,
                           Value *key,
                           Value *val,
                           const Location &loc,
                           int64_t flags = 0);
  Value *CreateForRange(Value *iters,
                        Value *callback,
                        Value *callback_ctx,
                        const Location &loc);
  Value *CreateForEachMapElem(Map &map,
                              Value *callback,
                              Value *callback_ctx,
                              const Location &loc);
  void CreateProbeRead(Value *dst,
                       llvm::Value *size,
                       Value *src,
                       AddrSpace as,
                       const Location &loc);
  // Emits a bpf_probe_read call in which the size is derived from the SizedType
  // argument. Has special handling for certain types such as pointers where the
  // size depends on the host system as well as the probe type.
  // If provided, the optional AddrSpace argument is used instead of the type's
  // address space (which may not always be set).
  void CreateProbeRead(Value *dst,
                       const SizedType &type,
                       Value *src,
                       const Location &loc,
                       std::optional<AddrSpace> addrSpace = std::nullopt);
  // Emits the load instruction the type of which is derived from the provided
  // SizedType. Used to access elements from structures that ctx points to, or
  // those that have already been pulled onto the BPF stack. Correctly handles
  // pointer size differences (see CreateProbeRead).
  llvm::Value *CreateDatastructElemLoad(const SizedType &type,
                                        llvm::Value *ptr);
  CallInst *CreateProbeReadStr(Value *dst,
                               llvm::Value *size,
                               Value *src,
                               AddrSpace as,
                               const Location &loc);
  CallInst *CreateProbeReadStr(Value *dst,
                               size_t size,
                               Value *src,
                               AddrSpace as,
                               const Location &loc);
  Value *CreateStrncmp(Value *str1, Value *str2, uint64_t n, bool inverse);
  Value *CreateStrcontains(Value *haystack,
                           uint64_t haystack_sz,
                           Value *needle,
                           uint64_t needle_sz);
  Value *CreateIntegerArrayCmp(Value *val1,
                               Value *val2,
                               const SizedType &val1_type,
                               const SizedType &val2_type,
                               bool inverse,
                               const Location &loc,
                               MDNode *metadata);
  Value *CreateGetNs(TimestampMode ts, const Location &loc);
  CallInst *CreateJiffies64(const Location &loc);
  CallInst *CreateGetCurrentCgroupId(const Location &loc);
  CallInst *CreateGetUidGid(const Location &loc);
  CallInst *CreateGetCpuId(const Location &loc);
  CallInst *CreateGetCurrentTask(const Location &loc);
  CallInst *CreateGetRandom(const Location &loc);
  CallInst *CreateGetStack(Value *ctx,
                           Value *buf,
                           const StackType& stack_type,
                           const Location &loc);
  CallInst *CreateGetFuncIp(Value *ctx, const Location &loc);
  CallInst *CreatePerCpuPtr(Value *var, Value *cpu, const Location &loc);
  CallInst *CreateThisCpuPtr(Value *var, const Location &loc);
  CallInst *CreateGetSocketCookie(Value *var, const Location &loc);
  Value *CreateGetStrAllocation(const std::string &name,
                                const Location &loc,
                                uint64_t pad = 0);
  Value *CreateGetFmtStringArgsAllocation(StructType *struct_type,
                                          const std::string &name,
                                          const Location &loc);
  Value *CreateTupleAllocation(const SizedType &tuple_type,
                               const std::string &name,
                               const Location &loc);
  Value *CreateKUStackAllocation(const SizedType &stack_type,
                               const std::string &name,
                               const Location &loc);
  Value *CreateJoinAllocation(const Location &loc);
  Value *CreateWriteMapValueAllocation(const SizedType &value_type,
                                       const std::string &name,
                                       const Location &loc);
  Value *CreateVariableAllocationInit(const SizedType &value_type,
                                      const std::string &name,
                                      const Location &loc);
  Value *CreateMapKeyAllocation(const SizedType &value_type,
                                const std::string &name,
                                const Location &loc);
  void CreateCheckSetRecursion(const Location &loc, int early_exit_ret);
  void CreateUnSetRecursion(const Location &loc);
  CallInst *CreateHelperCall(bpf_func_id func_id,
                             FunctionType *helper_type,
                             ArrayRef<Value *> args,
                             bool is_pure,
                             const Twine &Name,
                             const Location &loc);
  CallInst *createCall(FunctionType *callee_type,
                       Value *callee,
                       ArrayRef<Value *> args,
                       const Twine &Name);
  void CreateGetCurrentComm(AllocaInst *buf, size_t size, const Location &loc);
  void CreateOutput(Value *data, size_t size, const Location &loc);
  void CreateIncEventLossCounter(const Location &loc);
  void CreatePerCpuMapElemInit(Map &map,
                               Value *key,
                               Value *val,
                               const Location &loc);
  void CreatePerCpuMapElemAdd(Map &map,
                              Value *key,
                              Value *val,
                              const Location &loc);
  void CreateDebugOutput(std::string fmt_str,
                         const std::vector<Value *> &values,
                         const Location &loc);
  void CreateTracePrintk(Value *fmt,
                         Value *fmt_size,
                         const std::vector<Value *> &values,
                         const Location &loc);
  void CreateSignal(Value *sig, const Location &loc, bool target_thread);
  void CreateRuntimeError(RuntimeErrorId rte_id, const Location &loc);
  void CreateRuntimeError(RuntimeErrorId rte_id,
                          Value *return_value,
                          bpf_func_id func_id,
                          const Location &loc);
  void CreateHelperErrorCond(Value *return_value,
                             bpf_func_id func_id,
                             const Location &loc);
  StructType *GetStackStructType(const StackType& stack_type);
  StructType *GetStructType(const std::string &name,
                            const std::vector<llvm::Type *> &elements,
                            bool packed = false);
  Value *CreateGetPid(const Location &loc, bool force_init);
  Value *CreateGetTid(const Location &loc, bool force_init);
  AllocaInst *CreateUSym(Value *val, int probe_id, const Location &loc);
  Value *CreateRegisterRead(Value *ctx, const std::string &builtin);
  Value *CreateRegisterRead(Value *ctx, size_t offset, const std::string &name);
  Value *CreateKFuncArg(Value *ctx, SizedType &type, std::string &name);
  Value *CreateRawTracepointArg(Value *ctx, const std::string &builtin);
  Value *CreateUprobeArgsRecord(Value *ctx, const SizedType &args_type);
  llvm::Type *UprobeArgsType(const SizedType &args_type);
  CallInst *CreateSkbOutput(Value *skb,
                            Value *len,
                            AllocaInst *data,
                            size_t size);
  void CreatePath(Value *buf, Value *path, Value *sz, const Location &loc);
  void CreateSeqPrintf(Value *ctx,
                       Value *fmt,
                       Value *fmt_size,
                       Value *data,
                       Value *data_len,
                       const Location &loc);

  // For a type T, creates an integer expression representing the byte offset
  // of the element at the given index in T[]. Used for array dereferences and
  // pointer arithmetic.
  llvm::Value *CreatePtrOffset(const SizedType &type, llvm::Value *index);

  // Safely handle pointer references by wrapping the address with the
  // intrinsic `preserve_static_offset` [1], which will ensure that LLVM does
  // not apply certain basic optimizations (notably, saving any intermediate
  // offset from this pointer). This is required for the context pointer,
  // which, if modified. will trigger an error in the verifier. This method
  // also automatically handles casts from integers and other pointers; the
  // output value is always a pointer to `ty`.
  //
  // [1] https://reviews.llvm.org/D133361
  llvm::Value *CreateSafeGEP(llvm::Type *Ty,
                             llvm::Value *Ptr,
                             llvm::ArrayRef<Value *> offsets,
                             const llvm::Twine &Name = "");

  StoreInst *createAlignedStore(Value *val, Value *ptr, unsigned align);
  // moves the insertion point to the start of the function you're inside,
  // invokes functor, then moves the insertion point back to its original
  // position. this enables you to emit instructions at the start of your
  // function. you might want to "hoist" an alloca to make it available to
  // blocks that do not follow from yours, for example to make $a accessible in
  // both branches here:
  // begin { if (nsecs > 0) { $a = 1 } else { $a = 2 } print($a); exit() }
  void hoist(const std::function<void()> &functor);

  // Returns the integer type used to represent pointers in traced code.
  llvm::Type *getPointerStorageTy();

  void CreateMinMax(Value *val,
                    Value *val_ptr,
                    Value *is_set_ptr,
                    bool max,
                    bool is_signed);

  llvm::Value *CreateCheckedBinop(Binop &binop, Value *lhs, Value *rhs);

  // Check to see if the current basic block already has a terminator. This is
  // useful in cases where you've generated a nested block, but it may already
  // have a terminator and you can't unconditionally generate another.
  //
  // For example:
  //   if foo {
  //     return;
  //   } else {
  //     ...
  //   }
  bool HasTerminator();

private:
  Module &module_;
  BPFtrace &bpftrace_;
  AsyncIds &async_ids_;

  CallInst *CreateGetPidTgid(const Location &loc);
  void CreateGetNsPidTgid(Value *dev,
                          Value *ino,
                          AllocaInst *ret,
                          const Location &loc);
  llvm::Type *BpfPidnsInfoType();
  CallInst *createMapLookup(const std::string &map_name,
                            Value *key,
                            const std::string &name = "lookup_elem");
  CallInst *createPerCpuMapLookup(
      const std::string &map_name,
      Value *key,
      Value *cpu,
      const std::string &name = "lookup_percpu_elem");
  CallInst *createPerCpuMapLookup(
      const std::string &map_name,
      Value *key,
      Value *cpu,
      PointerType *val_ptr_ty,
      const std::string &name = "lookup_percpu_elem");
  Value *CreateReadMapValueAllocation(const SizedType &value_type,
                                      const std::string &name,
                                      const Location &loc);
  Value *createAllocation(std::string_view global_var_name,
                          llvm::Type *obj_type,
                          const std::string &name,
                          const Location &loc,
                          std::optional<std::function<size_t(AsyncIds &)>>
                              gen_async_id_cb = std::nullopt);
  void CreateAllocationInit(const SizedType &stype, Value *alloc);
  Value *createScratchBuffer(std::string_view global_var_name,
                             const Location &loc,
                             size_t key);
  bpf_func_id selectProbeReadHelper(AddrSpace as, bool str);

  void CreateRingbufOutput(Value *data, size_t size, const Location &loc);

  void createPerCpuSum(AllocaInst *ret, CallInst *call, const SizedType &type);
  void createPerCpuMinMax(AllocaInst *ret,
                          AllocaInst *is_ret_set,
                          CallInst *call,
                          const SizedType &type);
  void createPerCpuAvg(AllocaInst *total,
                       AllocaInst *count,
                       CallInst *call,
                       const SizedType &type);

  std::map<std::string, StructType *> structs_;
  llvm::Function *preserve_static_offset_ = nullptr;
};

} // namespace bpftrace::ast
