#pragma once

#include "ast.h"
#include "bpftrace.h"

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

  AllocaInst *CreateAllocaBPF(int array_size=1, const std::string &name="");
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

private:
  Module &module_;
  BPFtrace &bpftrace_;
};

} // namespace ast
} // namespace bpftrace
