#pragma once

#include <llvm/IR/DIBuilder.h>

namespace bpftrace {
namespace ast {

using namespace llvm;

class DIBuilderBPF : public DIBuilder
{
public:
  DIBuilderBPF(Module &module);

  void createFunctionDebugInfo(Function &func);

  DIType *getInt64Ty();
  DIType *getInt8PtrTy();

  DIFile *file = nullptr;

private:
  struct
  {
    DIType *int64 = nullptr;
    DIType *int8_ptr = nullptr;
  } types_;
};

} // namespace ast
} // namespace bpftrace
