#include "codegen_helper.h"
#include "bpffeature.h"
#include "globalvars.h"

namespace bpftrace::ast {

StorageLocation getAssignMapStatementStorageLocation(
    const AssignMapStatement &assignment)
{
  const auto &map = *assignment.map;
  const auto &expr_type = assignment.expr->type;
  if (shouldBeInBpfMemoryAlready(expr_type)) {
    if (expr_type.IsSameSizeRecursive(map.type)) {
      return StorageLocation::ALREADY_IN_MEMORY;
    }
  } else if (map.type.IsRecordTy() || map.type.IsArrayTy()) {
    if (expr_type.is_internal) {
      return StorageLocation::ALREADY_IN_MEMORY;
    }
  }
  return exceedsMapValueScratchBufferThreshold(map)
             ? StorageLocation::SCRATCH_BUFFER
             : StorageLocation::STACK;
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

bool exceedsMapValueScratchBufferThreshold(const Map &map)
{
  return map.type.GetSize() > globalvars::MAP_VAL_SCRATCH_THRESHOLD;
}

} // namespace bpftrace::ast
