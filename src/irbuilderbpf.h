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

  AllocaInst *CreateAllocaBPF(const SizedType &stype, const std::string &name="");
  AllocaInst *CreateAllocaMapKey(int bytes, const std::string &name="");
  void        CreateMemcpy(Value *dst, Value *src, Value *len);
  CallInst   *CreateBpfPseudoCall(int mapfd);
  CallInst   *CreateBpfPseudoCall(Map &map);
  LoadInst   *CreateMapLookupElem(Map &map, AllocaInst *key);
  void        CreateMapUpdateElem(Map &map, AllocaInst *key, Value *val);
  void        CreateMapDeleteElem(Map &map, AllocaInst *key);
  void        CreateProbeRead(AllocaInst *dst, Value *size, Value *src);
  CallInst   *CreateGetNs();
  CallInst   *CreateGetPidTgid();
  CallInst   *CreateGetUidGid();
  CallInst   *CreateGetStackId(Value *ctx, bool ustack);
  void        CreateGetCurrentComm(AllocaInst *buf, Value *size);

private:
  Module &module_;
  BPFtrace &bpftrace_;
};

} // namespace ast
} // namespace bpftrace
