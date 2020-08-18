#pragma once
#include "bpftrace.h"

// this file is for storage concerns shared between semantic_analyser and
// codegen_llvm
namespace bpftrace {
namespace ast {

inline bool needMapStorage(const SizedType &stype)
{
  // TODO: consider a threshold size
  return stype.IsAggregate();
}

} // namespace ast
} // namespace bpftrace
