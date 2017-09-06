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
  AllocaInst *CreateAllocaMapKey(int bytes, const std::string &name="");
  void        CreateMemcpy(Value *dst, Value *src, size_t len);
  void        CreateMemset(Value *dst, Value *val, size_t len);
  CallInst   *CreateBpfPseudoCall(int mapfd);
  CallInst   *CreateBpfPseudoCall(Map &map);
  Value      *CreateMapLookupElem(Map &map, AllocaInst *key);
  void        CreateMapUpdateElem(Map &map, AllocaInst *key, Value *val);
  void        CreateMapDeleteElem(Map &map, AllocaInst *key);
  void        CreateProbeRead(AllocaInst *dst, size_t size, Value *src);
  void        CreateProbeReadStr(AllocaInst *dst, size_t size, Value *src);
  CallInst   *CreateGetNs();
  CallInst   *CreateGetPidTgid();
  CallInst   *CreateGetUidGid();
  CallInst   *CreateGetCpuId();
  CallInst   *CreateGetStackId(Value *ctx, bool ustack);
  void        CreateGetCurrentComm(AllocaInst *buf, size_t size);
  void        CreatePerfEventOutput(Value *ctx, Value *data, size_t size);

private:
  Module &module_;
  BPFtrace &bpftrace_;
};

} // namespace ast
} // namespace bpftrace
