#pragma once

#include "ast.h"
#include "bpftrace.h"
#include "types.h"
#include <bcc/bcc_usdt.h>

#include <llvm/Config/llvm-config.h>
#include <llvm/IR/IRBuilder.h>

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
                       size_t size,
                       Value *src,
                       AddrSpace as,
                       const location &loc);
  void CreateProbeRead(Value *ctx,
                       Value *dst,
                       llvm::Value *size,
                       Value *src,
                       AddrSpace as,
                       const location &loc);
  CallInst *CreateProbeReadStr(Value *ctx,
                               AllocaInst *dst,
                               llvm::Value *size,
                               Value *src,
                               AddrSpace as,
                               const location &loc);
  CallInst *CreateProbeReadStr(Value *ctx,
                               AllocaInst *dst,
                               size_t size,
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
  Value *CreateStrcmp(Value *ctx,
                      Value *val,
                      AddrSpace as,
                      std::string str,
                      const location &loc,
                      bool inverse = false);
  Value *CreateStrcmp(Value *ctx,
                      Value *val1,
                      AddrSpace as1,
                      Value *val2,
                      AddrSpace as2,
                      const location &loc,
                      bool inverse = false);
  Value *CreateStrncmp(Value *ctx,
                       Value *val,
                       AddrSpace as,
                       std::string str,
                       uint64_t n,
                       const location &loc,
                       bool inverse = false);
  Value *CreateStrncmp(Value *ctx,
                       Value *val1,
                       AddrSpace as1,
                       Value *val2,
                       AddrSpace as2,
                       uint64_t n,
                       const location &loc,
                       bool inverse = false);
  CallInst *CreateGetNs(bool boot_time);
  CallInst   *CreateGetPidTgid();
  CallInst   *CreateGetCurrentCgroupId();
  CallInst   *CreateGetUidGid();
  CallInst   *CreateGetCpuId();
  CallInst   *CreateGetCurrentTask();
  CallInst   *CreateGetRandom();
  CallInst   *CreateGetStackId(Value *ctx, bool ustack, StackType stack_type, const location& loc);
  CallInst   *CreateGetJoinMap(Value *ctx, const location& loc);
  CallInst   *createCall(Value *callee, ArrayRef<Value *> args, const Twine &Name);
  void        CreateGetCurrentComm(Value *ctx, AllocaInst *buf, size_t size, const location& loc);
  void        CreatePerfEventOutput(Value *ctx, Value *data, size_t size);
  void        CreateSignal(Value *ctx, Value *sig, const location &loc);
  void        CreateOverrideReturn(Value *ctx, Value *rc);
  void        CreateHelperError(Value *ctx, Value *return_value, libbpf::bpf_func_id func_id, const location& loc);
  void        CreateHelperErrorCond(Value *ctx, Value *return_value, libbpf::bpf_func_id func_id, const location& loc, bool compare_zero=false);
  StructType *GetStructType(std::string name, const std::vector<llvm::Type *> & elements, bool packed = false);
  AllocaInst *CreateUSym(llvm::Value *val);
  Value      *CreatKFuncArg(Value *ctx, SizedType& type, std::string& name);
  void CreatePath(Value *ctx,
                  AllocaInst *buf,
                  Value *path,
                  const location &loc);
  void CreateSeqPrintf(Value *ctx,
                       Value *fmt,
                       Value *fmt_size,
                       AllocaInst *data,
                       Value *data_len,
                       const location &loc);
  // moves the insertion point to the start of the function you're inside,
  // invokes functor, then moves the insertion point back to its original
  // position. this enables you to emit instructions at the start of your
  // function. you might want to "hoist" an alloca to make it available to
  // blocks that do not follow from yours, for example to make $a accessible in
  // both branches here:
  // BEGIN { if (nsecs > 0) { $a = 1 } else { $a = 2 } print($a); exit() }
  void hoist(const std::function<void()> &functor);
  int helper_error_id_ = 0;

private:
  Module &module_;
  BPFtrace &bpftrace_;

  Value *CreateUSDTReadArgument(Value *ctx,
                                struct bcc_usdt_argument *argument,
                                Builtin &builtin,
                                AddrSpace as,
                                const location &loc);
  CallInst *createMapLookup(int mapid, Value *key);
  Constant *createProbeReadStrFn(llvm::Type *dst,
                                 llvm::Type *src,
                                 AddrSpace as);
  libbpf::bpf_func_id selectProbeReadHelper(AddrSpace as, bool str);

  std::map<std::string, StructType *> structs_;
};

} // namespace ast
} // namespace bpftrace
