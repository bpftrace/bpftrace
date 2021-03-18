#include "fake_map.h"

namespace bpftrace {

int FakeMap::next_mapfd_ = 1;

FakeMap::FakeMap(const std::string &name,
                 const SizedType &type __attribute__((unused)),
                 const MapKey &key __attribute__((unused)),
                 int min __attribute__((unused)),
                 int max __attribute__((unused)),
                 int step __attribute__((unused)),
                 int max_entries __attribute__((unused)))
{
  name_ = name;
  mapfd_ = next_mapfd_++;
}

FakeMap::FakeMap(const std::string &name,
                 const SizedType &type __attribute__((unused)),
                 const MapKey &key __attribute__((unused)),
                 int max_entries __attribute__((unused)))
{
  name_ = name;
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
