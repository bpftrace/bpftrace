#include <iostream>
#include <unistd.h>
#include <linux/version.h>

#include "common.h"
#include "libbpf.h"

#include "map.h"

namespace bpftrace {

Map::Map(const std::string &name, const SizedType &type, const MapKey &key, int min, int max, int step)
{
  name_ = name;
  type_ = type;
  key_ = key;
  // for lhist maps:
  lqmin = min;
  lqmax = max;
  lqstep = step;

  int key_size = key.size();
  if (type.type == Type::hist || type.type == Type::lhist ||
      type.type == Type::avg || type.type == Type::stats)
    key_size += 8;
  if (key_size == 0)
    key_size = 8;

  int max_entries = 128;
  enum bpf_map_type map_type;
  if ((type.type == Type::hist || type.type == Type::lhist || type.type == Type::count ||
      type.type == Type::sum || type.type == Type::min || type.type == Type::max ||
      type.type == Type::avg || type.type == Type::stats) &&
      (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)))
  {
      map_type = BPF_MAP_TYPE_PERCPU_HASH;
  }
  else if (type.type == Type::join)
  {
    map_type = BPF_MAP_TYPE_PERCPU_ARRAY;
    max_entries = 1;
    key_size = 4;
  }
  else
    map_type = BPF_MAP_TYPE_HASH;

  int value_size = type.size;
  int flags = 0;
  mapfd_ = bpf_create_map(map_type, name.c_str(), key_size, value_size, max_entries, flags);
  if (mapfd_ < 0)
  {
    std::cerr << "Error creating map: '" << name_ << "'" << std::endl;
  }
}

Map::Map(enum bpf_map_type map_type)
{
  int key_size, value_size, max_entries, flags;

  std::string name;
  if (map_type == BPF_MAP_TYPE_STACK_TRACE)
  {
    name = "stack";
    key_size = 4;
    value_size = sizeof(uintptr_t) * MAX_STACK_SIZE;
    max_entries = 128;
    flags = 0;
  }
  else if (map_type == BPF_MAP_TYPE_PERF_EVENT_ARRAY)
  {
    std::vector<int> cpus = ebpf::get_online_cpus();
    name = "printf";
    key_size = 4;
    value_size = 4;
    max_entries = cpus.size();
    flags = 0;
  }
  else
  {
    abort();
  }
  mapfd_ = bpf_create_map(map_type, name.c_str(), key_size, value_size, max_entries, flags);
  if (mapfd_ < 0)
  {
    std::string name;
    switch (map_type)
    {
      case BPF_MAP_TYPE_STACK_TRACE:
        name = "stack id";
        break;
      case BPF_MAP_TYPE_PERF_EVENT_ARRAY:
        name = "perf event";
        break;
      default:
        abort();
    }

    std::cerr << "Error creating " << name << " map (" << mapfd_ << ")" << std::endl;
  }
}

Map::~Map()
{
  if (mapfd_ >= 0)
    close(mapfd_);
}

} // namespace bpftrace
