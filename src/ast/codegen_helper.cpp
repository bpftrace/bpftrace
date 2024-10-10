#include "codegen_helper.h"
#include "bpffeature.h"
#include "globalvars.h"

namespace bpftrace::ast {

bool useAssignMapStatementScratchBuffer(const AssignMapStatement &assignment)
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

libbpf::bpf_map_type getUserDefinedMapType(const SizedType &val_type,
                                           const SizedType &key_type,
                                           BPFfeature &feature)
{
  if (val_type.IsCountTy() && key_type.IsNoneTy()) {
    return libbpf::BPF_MAP_TYPE_PERCPU_ARRAY;
  } else if (feature.has_map_percpu_hash() && val_type.NeedsPercpuMap()) {
    return libbpf::BPF_MAP_TYPE_PERCPU_HASH;
  } else if (!val_type.NeedsPercpuMap() && key_type.IsNoneTy()) {
    return libbpf::BPF_MAP_TYPE_ARRAY;
  } else {
    return libbpf::BPF_MAP_TYPE_HASH;
  }
}

bool canAggPerCpuMapElems(const SizedType &val_type,
                          const SizedType &key_type,
                          BPFfeature &feature)
{
  auto map_type = getUserDefinedMapType(val_type, key_type, feature);
  return val_type.IsCastableMapTy() &&
         (map_type == libbpf::BPF_MAP_TYPE_PERCPU_ARRAY ||
          map_type == libbpf::BPF_MAP_TYPE_PERCPU_HASH);
}

bool unopSkipAccept(Unop &unop)
{
  if (unop.expr->type.IsIntTy()) {
    if (unop.op == Operator::INCREMENT || unop.op == Operator::DECREMENT)
      return unop.expr->is_map || unop.expr->is_variable;
  }

  return false;
}

} // namespace bpftrace::ast
