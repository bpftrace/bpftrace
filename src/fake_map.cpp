#include "fake_map.h"

namespace bpftrace {

int FakeMap::next_mapfd_ = 1;

FakeMap::FakeMap(const std::string &name, const SizedType &type, const MapKey &key)
{
  mapfd_ = next_mapfd_++;
}

FakeMap::FakeMap(enum bpf_map_type map_type)
{
  mapfd_ = next_mapfd_++;
}


} // namespace bpftrace
