#pragma once

#include <optional>

#include "libbpf/bpf.h"
#include "types/types.h"

namespace bpftrace::types {

// A tuple is an anonymous struct.
Result<Struct> createTuple(BTF &btf, const std::vector<ValueType> &types);

// Defines a map.
struct MapInfo {
  ::bpf_map_type map_type;
  ValueType key;
  ValueType value;
  size_t nr_elements;
};

// A map as the standard specialized BTF definition.
Result<Struct> createMap(BTF &btf, const struct MapInfo &info);

// Returns the information for the map, if it is a map.
Result<std::optional<MapInfo>> getMapInfo(const AnyType &type);

} // namespace bpftrace::types
