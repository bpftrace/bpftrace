#include <unistd.h>

#include "map.h"
#include "libbpf.h"

namespace ebpf {
namespace bpftrace {

Map::Map() {
  mapfd_ = bpf_create_map(BPF_MAP_TYPE_HASH, 8, 8, 128, 0);
  // TODO check mapfd_ != -1
}

Map::~Map() {
  close(mapfd_);
}

} // namespace bpftrace
} // namespace ebpf
