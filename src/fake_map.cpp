#include "fake_map.h"

namespace bpftrace {

int FakeMap::next_mapfd_ = 1;

FakeMap::FakeMap(const std::string &name __attribute__((unused)),
                 const SizedType &type __attribute__((unused)),
                 const MapKey &key __attribute__((unused)))
{
  mapfd_ = next_mapfd_++;
}

FakeMap::FakeMap(const SizedType &type __attribute__((unused)))
{
  mapfd_ = next_mapfd_++;
}

FakeMap::FakeMap(enum bpf_map_type map_type __attribute__((unused)))
{
  mapfd_ = next_mapfd_++;
}


} // namespace bpftrace
