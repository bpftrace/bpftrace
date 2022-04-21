#pragma once

#include "bpftrace.h"

namespace bpftrace {
namespace ast {

inline bool needMemcpy(const SizedType &stype)
{
  return stype.IsAggregate() || stype.IsTimestampTy() || stype.IsCgroupPathTy();
}

inline bool shouldBeOnStackAlready(const SizedType &type)
{
  return type.IsStringTy() || type.IsBufferTy() || type.IsInetTy() ||
         type.IsUsymTy() || type.IsTupleTy() || type.IsTimestampTy() ||
         type.IsMacAddressTy() || type.IsCgroupPathTy();
}

inline bool onStack(const SizedType &type)
{
  return type.is_internal || shouldBeOnStackAlready(type);
}

inline AddrSpace find_addrspace_stack(const SizedType &ty)
{
  return (shouldBeOnStackAlready(ty)) ? AddrSpace::kernel : ty.GetAS();
}

} // namespace ast
} // namespace bpftrace
