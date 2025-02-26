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

namespace bpftrace {
namespace ast {

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
  llvm::Type *GetType(const SizedType &stype, bool emit_codegen_types = true);
  llvm::Type *GetMapValueType(const SizedType &stype);
  llvm::ConstantInt *GetIntSameSize(uint64_t C, llvm::Value *expr);
  llvm::ConstantInt *GetIntSameSize(uint64_t C, llvm::Type *ty);
  Value *GetMapVar(const std::string &map_name);
  Value *GetNull();
  CallInst *CreateMapLookup(Map &map,
                            Value *key,
                            const std::string &name = "lookup_elem");
  Value *CreateMapLookupElem(Value *ctx,
                             Map &map,
                             Value *key,
                             const location &loc);
  Value *CreateMapLookupElem(Value *ctx,
                             const std::string &map_name,
                             Value *key,
                             SizedType &type,
                             const location &loc);
  Value *CreatePerCpuMapAggElems(Value *ctx,
                                 Map &map,
                                 Value *key,
                                 const SizedType &type,
                                 const location &loc);
  void CreateMapUpdateElem(Value *ctx,
                           const std::string &map_ident,
                           Value *key,
                           Value *val,
                           const location &loc,
                           int64_t flags = 0);
  void CreateMapDeleteElem(Value *ctx,
                           Map &map,
                           Value *key,
                           const location &loc);
  Value *CreateForEachMapElem(Value *ctx,
                              Map &map,
                              Value *callback,
                              Value *callback_ctx,
                              const location &loc);
  void CreateProbeRead(Value *ctx,
                       Value *dst,
                       llvm::Value *size,
                       Value *src,
                       AddrSpace as,
                       const location &loc);
  // Emits a bpf_probe_read call in which the size is derived from the SizedType
  // argument. Has special handling for certain types such as pointers where the
  // size depends on the host system as well as the probe type.
  // If provided, the optional AddrSpace argument is used instead of the type's
  // address space (which may not always be set).
  void CreateProbeRead(Value *ctx,
                       Value *dest,
                       const SizedType &type,
                       Value *src,
                       const location &loc,
                       std::optional<AddrSpace> addrSpace = std::nullopt);
  // Emits the load instruction the type of which is derived from the provided
  // SizedType. Used to access elements from structures that ctx points to, or
  // those that have already been pulled onto the BPF stack. Correctly handles
  // pointer size differences (see CreateProbeRead).
  llvm::Value *CreateDatastructElemLoad(
      const SizedType &type,
      llvm::Value *ptr,
      bool isVolatile = false,
      std::optional<AddrSpace> addrSpace = std::nullopt);
  CallInst *CreateProbeReadStr(Value *ctx,
                               Value *dst,
                               llvm::Value *size,
                               Value *src,
                               AddrSpace as,
                               const location &loc);
  CallInst *CreateProbeReadStr(Value *ctx,
                               Value *dst,
                               size_t size,
                               Value *src,
                               AddrSpace as,
                               const location &loc);
  Value *CreateUSDTReadArgument(Value *ctx,
                                AttachPoint *attach_point,
                                int usdt_location_index,
                                int arg_name,
                                Builtin &builtin,
                                pid_t pid,
                                AddrSpace as,
                                const location &loc);
  Value *CreateStrncmp(Value *str1, Value *str2, uint64_t n, bool inverse);
  Value *CreateStrcontains(Value *val1,
                           uint64_t str1_size,
                           Value *val2,
                           uint64_t str2_size);
  Value *CreateIntegerArrayCmp(Value *ctx,
                               Value *val1,
                               Value *val2,
                               const SizedType &val1_type,
                               const SizedType &val2_type,
                               const bool inverse,
                               const location &loc,
                               MDNode *metadata);
  CallInst *CreateGetNs(TimestampMode ts, const location &loc);
  CallInst *CreateJiffies64(const location &loc);
  CallInst *CreateGetCurrentCgroupId(const location &loc);
  CallInst *CreateGetUidGid(const location &loc);
  CallInst *CreateGetNumaId(const location &loc);
  CallInst *CreateGetCpuId(const location &loc);
  CallInst *CreateGetCurrentTask(const location &loc);
  CallInst *CreateGetRandom(const location &loc);
  CallInst *CreateGetStack(Value *ctx,
                           bool ustack,
                           Value *buf,
                           StackType stack_type,
                           const location &loc);
  CallInst *CreateGetFuncIp(Value *ctx, const location &loc);
  CallInst *CreatePerCpuPtr(Value *var, Value *cpu, const location &loc);
  CallInst *CreateThisCpuPtr(Value *var, const location &loc);
  CallInst *CreateGetJoinMap(BasicBlock *failure_callback, const location &loc);
  CallInst *CreateGetStackScratchMap(StackType stack_type,
                                     BasicBlock *failure_callback,
                                     const location &loc);
  Value *CreateGetStrAllocation(const std::string &name, const location &loc);
  Value *CreateGetFmtStringArgsAllocation(StructType *struct_type,
                                          const std::string &name,
                                          const location &loc);
  Value *CreateTupleAllocation(const SizedType &tuple_type,
                               const std::string &name,
                               const location &loc);
  Value *CreateWriteMapValueAllocation(const SizedType &value_type,
                                       const std::string &name,
                                       const location &loc);
  Value *CreateVariableAllocationInit(const SizedType &value_type,
                                      const std::string &name,
                                      const location &loc);
  Value *CreateMapKeyAllocation(const SizedType &value_type,
                                const std::string &name,
                                const location &loc);
  void CreateCheckSetRecursion(const location &loc, int early_exit_ret);
  void CreateUnSetRecursion(const location &loc);
  CallInst *CreateHelperCall(libbpf::bpf_func_id func_id,
                             FunctionType *helper_type,
                             ArrayRef<Value *> args,
                             const Twine &Name,
                             const location *loc = nullptr);
  CallInst *createCall(FunctionType *callee_type,
                       Value *callee,
                       ArrayRef<Value *> args,
                       const Twine &Name);
  void CreateGetCurrentComm(Value *ctx,
                            AllocaInst *buf,
                            size_t size,
                            const location &loc);
  void CreateOutput(Value *ctx,
                    Value *data,
                    size_t size,
                    const location *loc = nullptr);
  void CreateAtomicIncCounter(const std::string &map_name, uint32_t idx);
  void CreateMapElemInit(Value *ctx,
                         Map &map,
                         Value *key,
                         Value *val,
                         const location &loc);
  void CreateMapElemAdd(Value *ctx,
                        Map &map,
                        Value *key,
                        Value *val,
                        const location &loc);
  void CreateDebugOutput(std::string fmt_str,
                         const std::vector<Value *> &values,
                         const location &loc);
  void CreateTracePrintk(Value *fmt,
                         Value *fmt_size,
                         const std::vector<Value *> &values,
                         const location &loc);
  void CreateSignal(Value *ctx, Value *sig, const location &loc);
  void CreateOverrideReturn(Value *ctx, Value *rc);
  void CreateHelperError(Value *ctx,
                         Value *return_value,
                         libbpf::bpf_func_id func_id,
                         const location &loc);
  void CreateHelperErrorCond(Value *ctx,
                             Value *return_value,
                             libbpf::bpf_func_id func_id,
                             const location &loc,
                             bool compare_zero = false);
  StructType *GetStackStructType(bool is_ustack);
  StructType *GetStructType(std::string name,
                            const std::vector<llvm::Type *> &elements,
                            bool packed = false);
  Value *CreateGetPid(const location &loc);
  Value *CreateGetTid(const location &loc);
  Value *CreateGetPid(Value *ctx, const location &loc);
  Value *CreateGetTid(Value *ctx, const location &loc);
  AllocaInst *CreateUSym(Value *ctx,
                         Value *val,
                         int probe_id,
                         const location &loc);
  Value *CreateRegisterRead(Value *ctx, const std::string &builtin);
  Value *CreateRegisterRead(Value *ctx, int offset, const std::string &name);
  Value *CreateKFuncArg(Value *ctx, SizedType &type, std::string &name);
  Value *CreateRawTracepointArg(Value *ctx, const std::string &builtin);
  Value *CreateUprobeArgsRecord(Value *ctx, const SizedType &args_type);
  llvm::Type *UprobeArgsType(const SizedType &args_type);
  CallInst *CreateSkbOutput(Value *skb,
                            Value *len,
                            AllocaInst *data,
                            size_t size);
  void CreatePath(Value *ctx,
                  Value *buf,
                  Value *path,
                  Value *sz,
                  const location &loc);
  void CreateSeqPrintf(Value *ctx,
                       Value *fmt,
                       Value *fmt_size,
                       Value *data,
                       Value *data_len,
                       const location &loc);

  // For a type T, creates an integer expression representing the byte offset
  // of the element at the given index in T[]. Used for array dereferences and
  // pointer arithmetic.
  llvm::Value *CreatePtrOffset(const SizedType &type,
                               llvm::Value *index,
                               AddrSpace as);

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
                             llvm::ArrayRef<Value *> IdxList,
                             const llvm::Twine &Name = "");

  StoreInst *createAlignedStore(Value *val, Value *ptr, unsigned align);
  // moves the insertion point to the start of the function you're inside,
  // invokes functor, then moves the insertion point back to its original
  // position. this enables you to emit instructions at the start of your
  // function. you might want to "hoist" an alloca to make it available to
  // blocks that do not follow from yours, for example to make $a accessible in
  // both branches here:
  // BEGIN { if (nsecs > 0) { $a = 1 } else { $a = 2 } print($a); exit() }
  void hoist(const std::function<void()> &functor);

  // Returns the integer type used to represent pointers in traced code.
  llvm::Type *getPointerStorageTy(AddrSpace as);

private:
  Module &module_;
  BPFtrace &bpftrace_;
  AsyncIds &async_ids_;

  CallInst *CreateGetPidTgid(const location &loc);
  void CreateGetNsPidTgid(Value *ctx,
                          Value *dev,
                          Value *ino,
                          AllocaInst *ret,
                          const location &loc);
  llvm::Type *BpfPidnsInfoType();
  Value *CreateUSDTReadArgument(Value *ctx,
                                struct bcc_usdt_argument *argument,
                                Builtin &builtin,
                                AddrSpace as,
                                const location &loc);
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
  CallInst *createGetScratchMap(const std::string &map_name,
                                const std::string &name,
                                const location &loc,
                                BasicBlock *failure_callback,
                                int key = 0);
  Value *CreateReadMapValueAllocation(const SizedType &value_type,
                                      const std::string &name,
                                      const location &loc);
  Value *createAllocation(globalvars::GlobalVar globalvar,
                          llvm::Type *obj_type,
                          const std::string &name,
                          const location &loc,
                          std::optional<std::function<size_t(AsyncIds &)>>
                              gen_async_id_cb = std::nullopt);
  void CreateAllocationInit(const SizedType &stype, Value *alloc);
  Value *createScratchBuffer(globalvars::GlobalVar globalvar,
                             const location &loc,
                             size_t key);
  libbpf::bpf_func_id selectProbeReadHelper(AddrSpace as, bool str);

  llvm::Type *getKernelPointerStorageTy();
  llvm::Type *getUserPointerStorageTy();
  void CreateRingbufOutput(Value *data,
                           size_t size,
                           const location *loc = nullptr);
  void CreatePerfEventOutput(Value *ctx,
                             Value *data,
                             size_t size,
                             const location *loc = nullptr);

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

} // namespace ast
} // namespace bpftrace
