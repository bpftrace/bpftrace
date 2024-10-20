#include "codegen_helper.h"

namespace bpftrace::ast {

bool needAssignMapStatementAllocation(const AssignMapStatement &assignment)
{
  const auto &map = *assignment.map;
  const auto &expr_type = assignment.expr->type;
  if (shouldBeInBpfMemoryAlready(expr_type)) {
    return !expr_type.IsSameSizeRecursive(map.type);
  } else if (map.type.IsRecordTy() || map.type.IsArrayTy()) {
    return !expr_type.is_internal;
  }
  return true;
}

} // namespace bpftrace::ast
