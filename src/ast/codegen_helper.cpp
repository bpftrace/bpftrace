#include "codegen_helper.h"

namespace bpftrace::ast {

// needAssignMapStatementAllocation determines if a map assignment requires a
// new memory allocation. This happens only in a few cases e.g. if there are
// two map assignments of tuples of different sizes e.g.
//   @x = ("xxx", 1); @x = ("xxxxxxx", 1);
// which requires a 0 memsetting and copying of each tuple element into the
// new allocation before calling bpf_map_update_elem.
//
// Another case when we need an allocation is for a external struct e.g.
//   $v = (struct task_struct *)arg1; @ = *$v;.
//
// Most cases we can reuse existing BPF memory and not create a new allocation.
//
// Note this function does NOT determine if an allocation should use scratch
// buffer or the stack, that logic is in
// IRBuilderBPF::CreateWriteMapValueAllocation
bool needAssignMapStatementAllocation(const AssignMapStatement &assignment)
{
  const auto &map = *assignment.map;
  const auto &expr_type = assignment.expr.type();
  if (shouldBeInBpfMemoryAlready(expr_type)) {
    return !expr_type.IsSameSizeRecursive(map.value_type);
  } else if (map.value_type.IsRecordTy() || map.value_type.IsArrayTy()) {
    return !expr_type.is_internal;
  }
  return true;
}

bool needMapKeyAllocation(const Map &map, const Expression &key_expr)
{
  if (inBpfMemory(key_expr.type())) {
    return !key_expr.type().IsSameSizeRecursive(map.key_type);
  }
  return true;
}

} // namespace bpftrace::ast
