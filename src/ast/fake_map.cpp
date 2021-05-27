#include "fake_map.h"

namespace bpftrace {

FakeMap::FakeMap(const std::string &name,
                 const SizedType &type __attribute__((unused)),
                 const MapKey &key __attribute__((unused)),
                 int min __attribute__((unused)),
                 int max __attribute__((unused)),
                 int step __attribute__((unused)),
                 int max_entries __attribute__((unused)))
{
  name_ = name;
  mapfd_ = 0;
}

FakeMap::FakeMap(const std::string &name,
                 const SizedType &type __attribute__((unused)),
                 const MapKey &key __attribute__((unused)),
                 int max_entries __attribute__((unused)))
{
  name_ = name;
  mapfd_ = 0;
}

FakeMap::FakeMap(const std::string &name,
                 enum bpf_map_type type __attribute__((unused)),
                 int key_size __attribute__((unused)),
                 int value_size __attribute__((unused)),
                 int max_entries __attribute__((unused)),
                 int flags __attribute__((unused)))
{
  name_ = name;
  mapfd_ = 0;
}

FakeMap::FakeMap(const SizedType &type __attribute__((unused)))
{
  mapfd_ = 0;
}

FakeMap::FakeMap(enum bpf_map_type map_type __attribute__((unused)))
{
  mapfd_ = 0;
}

} // namespace bpftrace
