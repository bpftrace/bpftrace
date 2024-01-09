#pragma once

#include <cstddef>
#include <string>

#include <bpf/libbpf.h>
#include <linux/bpf.h>

namespace libbpf {
#include "libbpf/bpf.h"
} // namespace libbpf

namespace bpftrace {

class BpfMap {
public:
  BpfMap(struct bpf_map *bpf_map) : bpf_map_(bpf_map)
  {
  }

  int fd = -1;

  libbpf::bpf_map_type type() const;
  std::string bpf_name() const;
  std::string name() const;
  uint32_t key_size() const;
  uint32_t value_size() const;
  uint32_t max_entries() const;

  bool is_stack_map() const;
  bool is_per_cpu_type() const;
  bool is_clearable() const;
  bool is_printable() const;

private:
  struct bpf_map *bpf_map_;
};

/**
   Internal map types
*/
enum class MapType {
  // Also update to_string
  PerfEvent,
  Join,
  Elapsed,
  MappedPrintfData,
  Ringbuf,
  RingbufLossCounter,
};

std::string to_string(MapType t);

// BPF maps do not accept "@" in name so we replace it by "AT_".
// The below two functions do the translations.
inline std::string bpf_map_name(const std::string &bpftrace_map_name)
{
  std::string name = bpftrace_map_name;
  if (name[0] == '@')
    name = "AT_" + name.substr(1);
  return name;
}

inline std::string bpftrace_map_name(const std::string &bpf_map_name)
{
  std::string name = bpf_map_name;
  if (name.compare(0, 3, "AT_") == 0)
    name = "@" + name.substr(3);
  return name;
}

inline bool is_bpf_map_clearable(libbpf::bpf_map_type map_type)
{
  return map_type != libbpf::BPF_MAP_TYPE_ARRAY &&
         map_type != libbpf::BPF_MAP_TYPE_PERCPU_ARRAY;
}

} // namespace bpftrace
