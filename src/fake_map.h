#pragma once

#include "map.h"

namespace bpftrace {

class FakeMap : public IMap
{
public:
  FakeMap(const std::string &name,
          const SizedType &type,
          const MapKey &key,
          int max_entries);
  FakeMap(const SizedType &type);
  FakeMap(enum bpf_map_type map_type);
  FakeMap(const std::string &name,
          enum bpf_map_type type,
          int key_size,
          int value_size,
          int max_entries,
          int flags);
};

} // namespace bpftrace
