#include "codegen_helper.h"

namespace bpftrace::ast {

bool needMapAllocation(const SizedType &src, const SizedType &dst)
{
  // For records (and records inside of tuples) the src and dst might have
  // fields out of order - for this case we need an allocation to copy
  // individual fields into so the original field ordering is preserved
  if (src.IsTupleTy() || src.IsRecordTy()) {
    if (src != dst) {
      return true;
    }
  }

  return !inBpfMemory(dst);
}

} // namespace bpftrace::ast
