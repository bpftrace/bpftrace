#pragma once

#include <string>

#include "mapkey.h"
#include "types.h"

#include <bcc/libbpf.h>

namespace bpftrace {

class IMap
{
public:
  IMap(const std::string &name,
       const SizedType &type,
       const MapKey &key,
       int max_entries)
      : IMap(name, type, key, 0, 0, 0, max_entries){};
  IMap(const std::string &name,
       const SizedType &type,
       const MapKey &key,
       int min,
       int max,
       int step,
       int max_entries);
  IMap(const std::string &name,
       enum bpf_map_type type,
       int key_size,
       int value_size,
       int max_entries,
       int flags);
  IMap(const SizedType &type);
  IMap(enum bpf_map_type map_type);
  virtual ~IMap() = default;
  IMap(const IMap &) = delete;
  IMap &operator=(const IMap &) = delete;

  // unique id of this map. Used by runtime to reference this map
  uint32_t id = static_cast<uint32_t>(-1);

  int mapfd_ = -1;
  std::string name_;
  SizedType type_;
  MapKey key_;
  enum bpf_map_type map_type_ = BPF_MAP_TYPE_UNSPEC;
  bool printable_ = true;

  // used by lhist(). TODO: move to separate Map object.
  int lqmin = 0;
  int lqmax = 0;
  int lqstep = 0;

  bool is_per_cpu_type()
  {
    return map_type_ == BPF_MAP_TYPE_PERCPU_HASH ||
           map_type_ == BPF_MAP_TYPE_PERCPU_ARRAY;
  }
  bool is_clearable() const
  {
    return map_type_ != BPF_MAP_TYPE_ARRAY &&
           map_type_ != BPF_MAP_TYPE_PERCPU_ARRAY;
  }
  bool is_printable() const
  {
    return printable_;
  }
};

} // namespace bpftrace
