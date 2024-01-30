#pragma once

#include <string>

#include "mapkey.h"
#include "types.h"

#include <linux/bpf.h>

namespace libbpf {
#include "libbpf/bpf.h"
} // namespace libbpf

namespace bpftrace {

class IMap {
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
       libbpf::bpf_map_type type,
       int key_size,
       int value_size,
       int max_entries,
       int flags);
  IMap(const SizedType &type);
  IMap(libbpf::bpf_map_type map_type);
  virtual ~IMap() = default;
  IMap(const IMap &) = delete;
  IMap &operator=(const IMap &) = delete;

  // unique id of this map. Used by runtime to reference this map
  uint32_t id = static_cast<uint32_t>(-1);

  int mapfd_ = -1;
  std::string name_;
  SizedType type_;
  MapKey key_;
  enum libbpf::bpf_map_type map_type_ = libbpf::BPF_MAP_TYPE_UNSPEC;
  bool printable_ = true;

  // used by lhist(). TODO: move to separate Map object.
  int lqmin = 0;
  int lqmax = 0;
  int lqstep = 0;

  int bits() const
  {
    return lqstep;
  } // used in "hist()"
  bool is_per_cpu_type()
  {
    return map_type_ == libbpf::BPF_MAP_TYPE_PERCPU_HASH ||
           map_type_ == libbpf::BPF_MAP_TYPE_PERCPU_ARRAY;
  }
  bool is_clearable() const
  {
    return map_type_ != libbpf::BPF_MAP_TYPE_ARRAY &&
           map_type_ != libbpf::BPF_MAP_TYPE_PERCPU_ARRAY;
  }
  bool is_printable() const
  {
    return printable_;
  }
};

} // namespace bpftrace
