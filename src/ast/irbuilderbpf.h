#pragma once

#include <bcc/bcc_usdt.h>

#include <llvm/Config/llvm-config.h>
#include <llvm/IR/IRBuilder.h>

#include <optional>

#include "ast/ast.h"
#include "bpftrace.h"
#include "types.h"

#if LLVM_VERSION_MAJOR >= 5 && LLVM_VERSION_MAJOR < 7
#define CREATE_MEMCPY(dst, src, size, algn)                                    \
  CreateMemCpy((dst), (src), (size), (algn))
#define CREATE_MEMCPY_VOLATILE(dst, src, size, algn)                           \
  CreateMemCpy((dst), (src), (size), (algn), true)
#elif LLVM_VERSION_MAJOR >= 7 && LLVM_VERSION_MAJOR < 10
#define CREATE_MEMCPY(dst, src, size, algn)                                    \
  CreateMemCpy((dst), (algn), (src), (algn), (size))
#define CREATE_MEMCPY_VOLATILE(dst, src, size, algn)                           \
  CreateMemCpy((dst), (algn), (src), (algn), (size), true)
#elif LLVM_VERSION_MAJOR >= 10
#define CREATE_MEMCPY(dst, src, size, algn)                                    \
  CreateMemCpy((dst), MaybeAlign(algn), (src), MaybeAlign(algn), (size))
#define CREATE_MEMCPY_VOLATILE(dst, src, size, algn)                           \
  CreateMemCpy((dst), MaybeAlign(algn), (src), MaybeAlign(algn), (size), true)
#else
#error Unsupported LLVM version
#endif

#if LLVM_VERSION_MAJOR >= 10
#define CREATE_MEMSET(ptr, val, size, align)                                   \
  CreateMemSet((ptr), (val), (size), MaybeAlign((align)))
#else
#define CREATE_MEMSET(ptr, val, size, align)                                   \
  CreateMemSet((ptr), (val), (size), (align))
#endif

#if LLVM_VERSION_MAJOR >= 13
#define CREATE_ATOMIC_RMW(op, ptr, val, align, order)                          \
  CreateAtomicRMW((op), (ptr), (val), MaybeAlign((align)), (order))
#else
#define CREATE_ATOMIC_RMW(op, ptr, val, align, order)                          \
  CreateAtomicRMW((op), (ptr), (val), (order))
#endif

namespace bpftrace {
namespace ast {

using namespace llvm;

class IRBuilderBPF : public IRBuilder<>
{
public:
  IRBuilderBPF(LLVMContext &context, Module &module, BPFtrace &bpftrace);

  AllocaInst *CreateAllocaBPF(llvm::Type *ty, const std::string &name="");
  AllocaInst *CreateAllocaBPF(const SizedType &stype, const std::string &name="");
  AllocaInst *CreateAllocaBPFInit(const SizedType &stype, const std::string &name);
  AllocaInst *CreateAllocaBPF(llvm::Type *ty, llvm::Value *arraysize, const std::string &name="");
  AllocaInst *CreateAllocaBPF(const SizedType &stype, llvm::Value *arraysize, const std::string &name="");
  AllocaInst *CreateAllocaBPF(int bytes, const std::string &name="");
  llvm::Type *GetType(const SizedType &stype);
  llvm::ConstantInt *GetIntSameSize(uint64_t C, llvm::Value *expr);
  llvm::ConstantInt *GetIntSameSize(uint64_t C, llvm::Type *ty);
  CallInst *CreateBpfPseudoCallId(int mapid);
  CallInst *CreateBpfPseudoCallId(Map &map);
  CallInst *CreateBpfPseudoCallValue(int mapid);
  CallInst *CreateBpfPseudoCallValue(Map &map);
  Value *CreateMapLookupElem(Value *ctx,
                             Map &map,
                             Value *key,
                             const location &loc);
  Value *CreateMapLookupElem(Value *ctx,
                             int mapid,
                             Value *key,
                             SizedType &type,
                             const location &loc);
  void CreateMapUpdateElem(Value *ctx,
                           Map &map,
                           Value *key,
                           Value *val,
                           const location &loc);
  void CreateMapDeleteElem(Value *ctx,
                           Map &map,
                           Value *key,
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
  Value *CreateStrncmp(Value *str1,
                       uint64_t str1_size,
                       Value *str2,
                       uint64_t str2_size,
                       uint64_t n,
                       bool inverse);
  Value *CreateStrcontains(Value *val1,
                           uint64_t str1_size,
                           Value *val2,
                           uint64_t str2_size,
                           bool inverse);
  Value *CreateIntegerArrayCmpUnrolled(Value *ctx,
                                       Value *val1,
                                       Value *val2,
                                       const SizedType &val1_type,
                                       const SizedType &val2_type,
                                       const bool inverse,
                                       const location &loc);
  Value *CreateIntegerArrayCmp(Value *ctx,
                               Value *val1,
                               Value *val2,
                               const SizedType &val1_type,
                               const SizedType &val2_type,
                               const bool inverse,
                               const location &loc,
                               MDNode *metadata);
  CallInst *CreateGetNs(TimestampMode ts, const location &loc);
  CallInst *CreateGetPidTgid(const location &loc);
  CallInst *CreateGetCurrentCgroupId(const location &loc);
  CallInst *CreateGetUidGid(const location &loc);
  CallInst *CreateGetNumaId(const location &loc);
  CallInst *CreateGetCpuId(const location &loc);
  CallInst *CreateGetCurrentTask(const location &loc);
  CallInst *CreateGetRandom(const location &loc);
  CallInst   *CreateGetStackId(Value *ctx, bool ustack, StackType stack_type, const location& loc);
  CallInst *CreateGetFuncIp(const location &loc);
  CallInst   *CreateGetJoinMap(Value *ctx, const location& loc);
  CallInst *CreateHelperCall(libbpf::bpf_func_id func_id,
                             FunctionType *helper_type,
                             ArrayRef<Value *> args,
                             const Twine &Name,
                             const location *loc = nullptr);
  CallInst *createCall(FunctionType *callee_type,
                       Value *callee,
                       ArrayRef<Value *> args,
                       const Twine &Name);
  void        CreateGetCurrentComm(Value *ctx, AllocaInst *buf, size_t size, const location& loc);
  void CreateOutput(Value *ctx,
                    Value *data,
                    size_t size,
                    const location *loc = nullptr);
  void CreateAtomicIncCounter(int mapfd, uint32_t idx);
  void CreateTracePrintk(Value *fmt,
                         Value *fmt_size,
                         const std::vector<Value *> &values,
                         const location &loc);
  void        CreateSignal(Value *ctx, Value *sig, const location &loc);
  void        CreateOverrideReturn(Value *ctx, Value *rc);
  void        CreateHelperError(Value *ctx, Value *return_value, libbpf::bpf_func_id func_id, const location& loc);
  void        CreateHelperErrorCond(Value *ctx, Value *return_value, libbpf::bpf_func_id func_id, const location& loc, bool compare_zero=false);
  StructType *GetStructType(std::string name, const std::vector<llvm::Type *> & elements, bool packed = false);
  AllocaInst *CreateUSym(llvm::Value *val, int probe_id, const location &loc);
  Value *CreateRegisterRead(Value *ctx, const std::string &builtin);
  Value *CreateRegisterRead(Value *ctx, int offset, const std::string &name);
  Value      *CreatKFuncArg(Value *ctx, SizedType& type, std::string& name);
  Value *CreateRawTracepointArg(Value *ctx, const std::string &builtin);
  Value *CreateUprobeArgsRecord(Value *ctx, const SizedType &args_type);
  llvm::Type *UprobeArgsType(const SizedType &args_type);
  CallInst *CreateSkbOutput(Value *skb,
                            Value *len,
                            AllocaInst *data,
                            size_t size);
  void CreatePath(Value *ctx,
                  AllocaInst *buf,
                  Value *path,
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

  StoreInst *createAlignedStore(Value *val, Value *ptr, unsigned align);
  // moves the insertion point to the start of the function you're inside,
  // invokes functor, then moves the insertion point back to its original
  // position. this enables you to emit instructions at the start of your
  // function. you might want to "hoist" an alloca to make it available to
  // blocks that do not follow from yours, for example to make $a accessible in
  // both branches here:
  // BEGIN { if (nsecs > 0) { $a = 1 } else { $a = 2 } print($a); exit() }
  void hoist(const std::function<void()> &functor);
  int helper_error_id_ = 0;

  // Returns the integer type used to represent pointers in traced code.
  llvm::Type *getPointerStorageTy(AddrSpace as);

private:
  Module &module_;
  BPFtrace &bpftrace_;

  Value *CreateUSDTReadArgument(Value *ctx,
                                struct bcc_usdt_argument *argument,
                                Builtin &builtin,
                                AddrSpace as,
                                const location &loc);
  CallInst *createMapLookup(int mapid, Value *key);
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

  std::map<std::string, StructType *> structs_;
};

} // namespace ast
} // namespace bpftrace
