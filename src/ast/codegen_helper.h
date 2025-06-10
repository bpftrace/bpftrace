#pragma once

#include "ast/ast.h"

namespace bpftrace::ast {

inline bool needMemcpy(const SizedType &stype)
{
  return stype.IsAggregate() || stype.IsTimestampTy() || stype.IsCgroupPathTy();
}

bool needAssignMapStatementAllocation(const AssignMapStatement &assignment);

bool needMapKeyAllocation(const Map &map, const Expression &key_expr);

} // namespace bpftrace::ast
