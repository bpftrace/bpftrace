#include "fake_map.h"

namespace bpftrace {

FakeMap::FakeMap(const std::string &name,
                 const SizedType &type,
                 const MapKey &key,
                 int max_entries)
    : IMap(name, type, key, max_entries)
{
}

FakeMap::FakeMap(const std::string &name,
                 enum bpf_map_type type,
                 int key_size,
                 int value_size,
                 int max_entries,
                 int flags)
    : IMap(name, type, key_size, value_size, max_entries, flags)
{
}

FakeMap::FakeMap(const SizedType &type) : IMap(type)
{
}

FakeMap::FakeMap(enum bpf_map_type map_type) : IMap(map_type)
{
}

} // namespace bpftrace
