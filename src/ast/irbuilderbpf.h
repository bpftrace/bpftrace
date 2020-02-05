#pragma once

#include "ast.h"
#include "bcc_usdt.h"
#include "bpftrace.h"
#include "types.h"

#include <llvm/Config/llvm-config.h>
#include <llvm/IR/IRBuilder.h>

#if LLVM_VERSION_MAJOR >= 5 && LLVM_VERSION_MAJOR < 7
#define CREATE_MEMCPY(dst, src, size, algn)                                    \
  CreateMemCpy((dst), (src), (size), (algn))
#define CREATE_MEMCPY_VOLATILE(dst, src, size, algn)                           \
  CreateMemCpy((dst), (src), (size), (algn), true)
#elif LLVM_VERSION_MAJOR >= 7
#define CREATE_MEMCPY(dst, src, size, algn)                                    \
  CreateMemCpy((dst), (algn), (src), (algn), (size))
#define CREATE_MEMCPY_VOLATILE(dst, src, size, algn)                           \
  CreateMemCpy((dst), (algn), (src), (algn), (size), true)
#else
#error Unsupported LLVM version
#endif

namespace bpftrace {
namespace ast {

using namespace llvm;

class IRBuilderBPF : public IRBuilder<>
{
public:
  IRBuilderBPF(LLVMContext &context, Module &module, BPFtrace &bpftrace);

  // clang-format off
  AllocaInst *CreateAllocaBPF(llvm::Type *ty, const std::string &name="");
  AllocaInst *CreateAllocaBPF(const SizedType &stype, const std::string &name="");
  AllocaInst *CreateAllocaBPFInit(const SizedType &stype, const std::string &name);
  AllocaInst *CreateAllocaBPF(llvm::Type *ty, llvm::Value *arraysize, const std::string &name="");
  AllocaInst *CreateAllocaBPF(const SizedType &stype, llvm::Value *arraysize, const std::string &name="");
  AllocaInst *CreateAllocaBPF(int bytes, const std::string &name="");
  llvm::Type *GetType(const SizedType &stype);
  llvm::ConstantInt *GetIntSameSize(uint64_t C, llvm::Value *expr);
  CallInst   *CreateBpfPseudoCall(int mapfd);
  CallInst   *CreateBpfPseudoCall(Map &map);
  Value      *CreateMapLookupElem(Map &map, AllocaInst *key);
  Value      *CreateMapLookupElem(int mapfd, AllocaInst *key, SizedType &type);
  void        CreateMapUpdateElem(Map &map, AllocaInst *key, Value *val);
  void        CreateMapDeleteElem(Map &map, AllocaInst *key);
  void        CreateProbeRead(AllocaInst *dst, size_t size, Value *src);
  CallInst   *CreateProbeReadStr(AllocaInst *dst, llvm::Value *size, Value *src);
  CallInst   *CreateProbeReadStr(AllocaInst *dst, size_t size, Value *src);
  CallInst   *CreateProbeReadStr(Value *dst, size_t size, Value *src);
  Value      *CreateUSDTReadArgument(Value *ctx, AttachPoint *attach_point, int arg_name, Builtin &builtin, int pid);
  Value      *CreateStrcmp(Value* val, std::string str, bool inverse=false);
  Value      *CreateStrcmp(Value* val1, Value* val2, bool inverse=false);
  Value      *CreateStrncmp(Value* val, std::string str, uint64_t n, bool inverse=false);
  Value      *CreateStrncmp(Value* val1, Value* val2, uint64_t n, bool inverse=false);
  CallInst   *CreateGetNs();
  CallInst   *CreateGetPidTgid();
  CallInst   *CreateGetCurrentCgroupId();
  CallInst   *CreateGetUidGid();
  CallInst   *CreateGetCpuId();
  CallInst   *CreateGetCurrentTask();
  CallInst   *CreateGetRandom();
  CallInst   *CreateGetStackId(Value *ctx, bool ustack, StackType stack_type);
  CallInst   *CreateGetJoinMap(Value *ctx);
  void        CreateGetCurrentComm(AllocaInst *buf, size_t size);
  void        CreatePerfEventOutput(Value *ctx, Value *data, size_t size);
  void        CreateSignal(Value *sig);
  void        CreateOverrideReturn(Value *ctx, Value *rc);

private:
  Module &module_;
  BPFtrace &bpftrace_;

  Value      *CreateUSDTReadArgument(Value *ctx, struct bcc_usdt_argument *argument, Builtin &builtin);
  CallInst   *createMapLookup(int mapfd, AllocaInst *key);
  // clang-format on
};

} // namespace ast
} // namespace bpftrace
