#pragma once

#include <concepts>
#include <string>
#include <unordered_set>

#include "ast/ast.h"
#include "types.h"

namespace bpftrace::ast {

inline bool needMemcpy(const SizedType &stype)
{
  return stype.IsAggregate() || stype.IsTimestampTy() || stype.IsCgroupPathTy();
}

inline AddrSpace find_addrspace_stack(const SizedType &ty)
{
  return ty.IsCtxAccess() ? AddrSpace::kernel : ty.GetAS();
}

// This applies to both map keys and map values
bool needMapAllocation(const SizedType &src, const SizedType &dst);

struct IterVars {
  std::unordered_set<std::string> scratch;
  std::unordered_set<std::string> state;
};

template <typename T>
  requires std::same_as<T, Probe> || std::same_as<T, Subprog>
IterVars collectIterVars(T &node);

} // namespace bpftrace::ast
