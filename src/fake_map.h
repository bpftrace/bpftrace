#pragma once

#include "imap.h"

namespace bpftrace {

class FakeMap : public IMap
{
public:
  FakeMap(const std::string &name,
          const SizedType &type,
          const MapKey &key,
          int max_entries = 0);
  FakeMap(const SizedType &type);
  FakeMap(enum bpf_map_type map_type);
  FakeMap(const std::string &name,
          const SizedType &type,
          const MapKey &key,
          int min,
          int max,
          int step,
          int max_entries);

  static int next_mapfd_;
};

} // namespace bpftrace
