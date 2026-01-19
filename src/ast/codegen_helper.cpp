#include "codegen_helper.h"

namespace bpftrace::ast {

bool needMapAllocation(const SizedType &ty)
{
  return !inBpfMemory(ty);
}

} // namespace bpftrace::ast
