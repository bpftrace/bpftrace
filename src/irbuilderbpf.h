#pragma once

#include "ast.h"
#include "bpftrace.h"

#include <llvm/IR/IRBuilder.h>

namespace ebpf {
namespace bpftrace {
namespace ast {

using namespace llvm;

class IRBuilderBPF : public IRBuilder<>
{
public:
  IRBuilderBPF(LLVMContext &context,
               Module &module,
               BPFtrace &bpftrace);

  AllocaInst *CreateAllocaBPF(llvm::Type *ty, const std::string &name="") const;
  CallInst   *CreateBpfPseudoCall(Map &map);
  LoadInst   *CreateMapLookupElem(Map &map, AllocaInst *key);
  void        CreateMapUpdateElem(Map &map, AllocaInst *key, AllocaInst *val);
  CallInst   *CreateGetNs();
  CallInst   *CreateGetPidTgid();
  CallInst   *CreateGetUidGid();

private:
  Module &module_;
  BPFtrace &bpftrace_;
};

} // namespace ast
} // namespace bpftrace
} // namespace ebpf
