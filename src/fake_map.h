#pragma once

#include "imap.h"

namespace bpftrace {

class FakeMap : public IMap {
public:
  FakeMap(const std::string &name, const SizedType &type, const MapKey &key);
  FakeMap(enum bpf_map_type map_type);

  static int next_mapfd_;
};

} // namespace bpftrace
