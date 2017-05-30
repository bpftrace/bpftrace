#include <iostream>
#include <unistd.h>

#include "map.h"
#include "libbpf.h"

namespace ebpf {
namespace bpftrace {

Map::Map(std::string &name, Type type, std::vector<Type> &args)
  : name_(name)
{
  int key_size = 0;
  if (args.size() > 0)
  {
    for (auto type : args)
    {
      switch (type)
      {
        case Type::integer:
          key_size += 8;
          break;
        default:
          abort();
      }
    }
  }
  else
  {
    key_size = 8;
  }
  if (type == Type::quantize)
  {
    key_size += 8;
  }

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
} // namespace ebpf
