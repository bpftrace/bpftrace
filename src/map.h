#pragma once

#include "imap.h"

namespace bpftrace {

class Map : public IMap {
public:
  Map(const std::string &name, const SizedType &type, const MapKey &key)
    : Map(name, type, key, 0, 0, 0) {};
  Map(const std::string &name, const SizedType &type, const MapKey &key, int min, int max, int step);
  Map(const SizedType &type);
  Map(enum bpf_map_type map_type);
  virtual ~Map() override;

  int create_map(enum bpf_map_type map_type, const char *name, int key_size, int value_size, int max_entries, int flags);
};

} // namespace bpftrace
