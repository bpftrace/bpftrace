#pragma once
#include "bpftrace.h"

namespace bpftrace {
namespace ast {

inline bool needMemcpy(const SizedType &stype)
{
  return stype.IsAggregate() || stype.IsTimestampTy();
}

inline bool shouldBeOnStackAlready(const SizedType &type)
{
  return type.IsStringTy() || type.IsBufferTy() || type.IsInetTy() ||
         type.IsUsymTy() || type.IsTupleTy() || type.IsTimestampTy();
}

} // namespace ast
} // namespace bpftrace
