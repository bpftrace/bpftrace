#include <iostream>
#include <unistd.h>

#include "map.h"
#include "libbpf.h"

namespace bpftrace {

Map::Map(std::string &name, Type type, MapKey key)
  : name_(name), type_(type), key_(key)
{
  int key_size = key.size();
  if (type == Type::quantize)
    key_size += 8;
  if (key_size == 0)
    key_size = 8;

  int value_size = 8;
  int max_entries = 128;
  int flags = 0;
  mapfd_ = bpf_create_map(BPF_MAP_TYPE_HASH, key_size, value_size, max_entries, flags);
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
