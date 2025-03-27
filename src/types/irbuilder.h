#pragma once

#include <llvm/IR/IRBuilder.h>

#include "types/types.h"

namespace bpftrace::types {

template <typename T>
struct defaultIRTypeFor {
  Result<llvm::Type *> operator()(llvm::IRBuilderBase &base,
                                  [[maybe_unused]] const T &t)
  {
    return base.getVoidTy();
  }
};

template <typename... Ts>
struct defaultIRTypeFor<VariantType<Ts...>> {
  Result<llvm::Type *> operator()(llvm::IRBuilderBase &base,
                                  const VariantType<Ts...> &type)
  {
    return std::visit([&](const auto &v) { return getType(base, v); },
                      type.value());
  }
};

Result<llvm::Type *> getType(llvm::IRBuilderBase &base, const Integer &type);
Result<llvm::Type *> getType(llvm::IRBuilderBase &base, const Pointer &type);
Result<llvm::Type *> getType(llvm::IRBuilderBase &base, const Array &type);
Result<llvm::Type *> getType(llvm::IRBuilderBase &base, const Struct &type);
Result<llvm::Type *> getType(llvm::IRBuilderBase &base, const Union &type);
Result<llvm::Type *> getType(llvm::IRBuilderBase &base, const Enum &type);
Result<llvm::Type *> getType(llvm::IRBuilderBase &base, const Enum64 &type);
Result<llvm::Type *> getType(llvm::IRBuilderBase &base, const Typedef &type);
Result<llvm::Type *> getType(llvm::IRBuilderBase &base, const Volatile &type);
Result<llvm::Type *> getType(llvm::IRBuilderBase &base, const Const &type);
Result<llvm::Type *> getType(llvm::IRBuilderBase &base, const Restrict &type);
Result<llvm::Type *> getType(llvm::IRBuilderBase &base,
                             const FunctionProto &type);

template <typename T>
Result<llvm::Type *> getType(llvm::IRBuilderBase &base, const T &type)
{
  defaultIRTypeFor<T> op;
  return op(base, type);
}

} // namespace bpftrace::types
