#pragma once

#include "bpftrace.h"

namespace bpftrace {
namespace ast {

inline bool needMemcpy(const SizedType &stype)
{
  return stype.IsAggregate() || stype.IsTimestampTy() || stype.IsCgroupPathTy();
}

// BPF memory is memory that the program can access with a regular
// dereference. This could mean the value is on the stack, a map, or
// maybe something else (like BPF arenas) in the future.
//
// This means that a bpf_probe_read_*() is _NOT_ required.
inline bool shouldBeInBpfMemoryAlready(const SizedType &type)
{
  return type.IsStringTy() || type.IsBufferTy() || type.IsInetTy() ||
         type.IsUsymTy() || type.IsKstackTy() || type.IsUstackTy() ||
         type.IsTupleTy() || type.IsTimestampTy() || type.IsMacAddressTy() ||
         type.IsCgroupPathTy();
}

inline bool inBpfMemory(const SizedType &type)
{
  return type.is_internal || shouldBeInBpfMemoryAlready(type);
}

inline AddrSpace find_addrspace_stack(const SizedType &ty)
{
  return (shouldBeInBpfMemoryAlready(ty)) ? AddrSpace::kernel : ty.GetAS();
}

bool needAssignMapStatementAllocation(const AssignMapStatement &assignment);

bool needMapKeyAllocation(const Map &map);
bool needMapKeyAllocation(const Map &map, Expression *key_expr);

} // namespace ast
} // namespace bpftrace
