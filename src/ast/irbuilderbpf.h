#pragma once

#include "ast.h"
#include "bpftrace.h"
#include "types.h"

#include <llvm/IR/IRBuilder.h>

namespace bpftrace {
namespace ast {

using namespace llvm;

class IRBuilderBPF : public IRBuilder<>
{
public:
  IRBuilderBPF(LLVMContext &context,
               Module &module,
               BPFtrace &bpftrace);

  AllocaInst *CreateAllocaBPF(llvm::Type *ty, const std::string &name="");
  AllocaInst *CreateAllocaBPF(const SizedType &stype, const std::string &name="");
  AllocaInst *CreateAllocaBPF(llvm::Type *ty, llvm::Value *arraysize, const std::string &name="");
  AllocaInst *CreateAllocaBPF(const SizedType &stype, llvm::Value *arraysize, const std::string &name="");
  AllocaInst *CreateAllocaBPF(int bytes, const std::string &name="");
  llvm::Type *GetType(const SizedType &stype);
  CallInst   *CreateBpfPseudoCall(int mapfd);
  CallInst   *CreateBpfPseudoCall(Map &map);
  Value      *CreateMapLookupElem(Map &map, AllocaInst *key);
  void        CreateMapUpdateElem(Map &map, AllocaInst *key, Value *val);
  void        CreateMapDeleteElem(Map &map, AllocaInst *key);
  void        CreateProbeRead(AllocaInst *dst, size_t size, Value *src);
  CallInst   *CreateProbeReadStr(AllocaInst *dst, size_t size, Value *src);
  CallInst   *CreateProbeReadStr(Value *dst, size_t size, Value *src);
  CallInst   *CreateGetNs();
  CallInst   *CreateGetPidTgid();
  CallInst   *CreateGetUidGid();
  CallInst   *CreateGetCpuId();
  CallInst   *CreateGetCurrentTask();
  CallInst   *CreateGetRandom();
  CallInst   *CreateGetStackId(Value *ctx, bool ustack);
  CallInst   *CreateGetJoinMap(Value *ctx);
  void        CreateGetCurrentComm(AllocaInst *buf, size_t size);
  void        CreatePerfEventOutput(Value *ctx, Value *data, size_t size);

private:
  Module &module_;
  BPFtrace &bpftrace_;
};

} // namespace ast
} // namespace bpftrace
