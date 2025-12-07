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
  const auto &map = *assignment.map_access;
  const auto &expr_type = assignment.expr.type();
  if (shouldBeInBpfMemoryAlready(expr_type)) {
    return false;
  } else if (map.map->value_type.IsRecordTy() ||
             map.map->value_type.IsArrayTy()) {
    return expr_type.GetAS() != AddrSpace::none;
  }
  return true;
}

bool needMapKeyAllocation(const Expression &key_expr)
{
  return !inBpfMemory(key_expr.type());
}

} // namespace bpftrace::ast
