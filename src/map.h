#pragma once

#include "imap.h"

namespace bpftrace {

class Map : public IMap {
public:
  Map(const std::string &name, const SizedType &type, const MapKey &key)
    : Map(name, type, key, 0, 0, 0) {};
  Map(const std::string &name, const SizedType &type, const MapKey &key, int min, int max, int step);
  Map(enum bpf_map_type map_type);
  virtual ~Map() override;
};

} // namespace bpftrace
