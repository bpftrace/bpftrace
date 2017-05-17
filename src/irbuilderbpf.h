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
  Value *CreateBpfPseudoCall(Map &map);
  Value *CreateMapLookupElem(Map &map, Value *key);
  void   CreateMapUpdateElem(Map &map, Value *key, Value *val);
  Value *CreateGetNs();
  Value *CreateGetPidTgid();
  Value *CreateGetUidGid();

private:
  Module &module_;
  BPFtrace &bpftrace_;
};

} // namespace ast
} // namespace bpftrace
} // namespace ebpf
