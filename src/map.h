#pragma once

#include "imap.h"

namespace bpftrace {

class Map : public IMap {
public:
  Map(const std::string &name, const SizedType &type, const MapKey &key);
  Map(enum bpf_map_type map_type);
  virtual ~Map() override;
};

} // namespace bpftrace
