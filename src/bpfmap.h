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

private:
  struct bpf_map *bpf_map_;
};

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

} // namespace bpftrace
