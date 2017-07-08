#include <iostream>
#include <unistd.h>

#include "map.h"
#include "libbpf.h"

namespace bpftrace {

Map::Map(const std::string &name, const SizedType &type, const MapKey &key)
  : name_(name), type_(type), key_(key)
{
  int key_size = key.size();
  if (type.type == Type::quantize)
    key_size += 8;
  if (key_size == 0)
    key_size = 8;

  int value_size = type.size;
  int max_entries = 128;
  int flags = 0;
  mapfd_ = bpf_create_map(BPF_MAP_TYPE_HASH, key_size, value_size, max_entries, flags);
  if (mapfd_ < 0)
  {
    std::cerr << "Error creating map: '" << name_ << "'" << std::endl;
  }
}

Map::Map(const std::string &name) : name_(name)
{
  // Only used for creating maps for storing stack IDs
  int key_size = 4;
  int value_size = sizeof(uintptr_t) * MAX_STACK_SIZE;
  int max_entries = 128;
  int flags = 0;
  mapfd_ = bpf_create_map(BPF_MAP_TYPE_STACK_TRACE, key_size, value_size, max_entries, flags);
  if (mapfd_ < 0)
  {
    std::cerr << "Error creating map: '" << name_ << "'" << std::endl;
  }
}

Map::~Map()
{
  close(mapfd_);
}

} // namespace bpftrace
