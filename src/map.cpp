#include <iostream>
#include <unistd.h>

#include "map.h"
#include "libbpf.h"

namespace ebpf {
namespace bpftrace {

Map::Map(std::string &name) : name_(name) {
  mapfd_ = bpf_create_map(BPF_MAP_TYPE_HASH, 8, 8, 128, 0);
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
