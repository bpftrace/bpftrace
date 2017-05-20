#include <iostream>
#include <unistd.h>

#include "map.h"
#include "libbpf.h"

namespace ebpf {
namespace bpftrace {

Map::Map(std::string &name, int key_size) : name_(name) {
  int value_size = 8;
  int max_entries = 128;
  int flags = 0;
  mapfd_ = bpf_create_map(BPF_MAP_TYPE_HASH, key_size, value_size, max_entries, flags);
  if (mapfd_ < 0)
  {
    std::cerr << "Error creating map: '" << name_ << "'" << std::endl;
  }
}

Map::~Map() {
  close(mapfd_);
}

} // namespace bpftrace
} // namespace ebpf
