#pragma once

#include "btf/btf.h"
#include "libbpf/bpf.h"

namespace bpftrace::btf {

// Indicates an error occured while parsing BTF.
class MapError : public ErrorInfo<MapError> {
public:
  static char ID;
  MapError(std::string msg) : msg_(std::move(msg)) {};
  void log(llvm::raw_ostream &OS) const override;

private:
  std::string msg_;
};

// A tuple is an anonymous struct.
Result<Struct> createTuple(Types &btf, const std::vector<ValueType> &types);

// Defines a map.
struct MapInfo {
  ::bpf_map_type map_type;
  AnyType key;
  AnyType value;
  size_t nr_elements;
};

// A map as the standard specialized Types definition.
Result<Struct> createMap(Types &btf, const struct MapInfo &info);

// Returns the information for the map, if it is a map.
Result<MapInfo> getMapInfo(const AnyType &type);

} // namespace bpftrace::btf
