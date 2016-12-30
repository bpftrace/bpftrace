#include <unistd.h>

#include "map.h"

namespace ebpf {
namespace bpftrace {

int Map::n = 0;

Map::Map() {
  // TODO create map here
  mapfd_ = n++;
}

Map::~Map() {
  close(mapfd_);
}

} // namespace bpftrace
} // namespace ebpf
