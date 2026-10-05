#pragma once

#include "ast/ast.h"
#include "types.h"

namespace bpftrace::ast {

inline bool needMemcpy(const SizedType &stype)
{
  return stype.IsAggregate() || stype.IsTimestampTy() || stype.IsCgroupPathTy();
}

inline AddrSpace find_addrspace_stack(const SizedType &ty)
{
  return ty.IsInBpfMemory() ? AddrSpace::kernel : ty.GetAS();
}

// This applies to both map keys and map values
bool needMapAllocation(const SizedType &src, const SizedType &dst);

} // namespace bpftrace::ast
