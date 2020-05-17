#pragma once

#include <string>

#include "mapkey.h"
#include "types.h"

#include <bcc/libbpf.h>

namespace bpftrace {

class IMap
{
public:
  virtual ~IMap() { }
  IMap() { }
  IMap(const IMap &) = delete;
  IMap &operator=(const IMap &) = delete;

  int mapfd_;
  std::string name_;
  SizedType type_;
  MapKey key_;
  enum bpf_map_type map_type_;
  int max_entries_;
  bool is_per_cpu_type()
  {
    return map_type_ == BPF_MAP_TYPE_PERCPU_HASH ||
           map_type_ == BPF_MAP_TYPE_PERCPU_ARRAY;
  }

  // unique id of this map. Used by (bpf) runtime to reference
  // this map
  uint32_t id;
  // used by lhist(). TODO: move to separate Map object.
  int lqmin;
  int lqmax;
  int lqstep;
};

} // namespace bpftrace
