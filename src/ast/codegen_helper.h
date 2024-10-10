#pragma once

#include "bpffeature.h"
#include "bpftrace.h"

namespace bpftrace {
namespace ast {

enum class StorageLocation {
  SCRATCH_BUFFER,
  STACK,
  ALREADY_IN_MEMORY,
};

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

StorageLocation getAssignMapStatementStorageLocation(
    const AssignMapStatement &assignment);

bool exceedsMapValueScratchBufferThreshold(const Map &map);

libbpf::bpf_map_type getUserDefinedMapType(const SizedType &val_type,
                                           const SizedType &key_type,
                                           BPFfeature &feature);

} // namespace ast
} // namespace bpftrace
