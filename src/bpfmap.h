#pragma once

#include <optional>
#include <string>
#include <string_view>

#include <bpf/libbpf.h>
#include <linux/bpf.h>

#include "types.h"

namespace libbpf {
#include "libbpf/bpf.h"
} // namespace libbpf

namespace bpftrace {

class BpfMap {
public:
  BpfMap(struct bpf_map *bpf_map)
      : bpf_map_(bpf_map),
        type_(static_cast<libbpf::bpf_map_type>(bpf_map__type(bpf_map))),
        name_(bpf_map__name(bpf_map)),
        key_size_(bpf_map__key_size(bpf_map)),
        value_size_(bpf_map__value_size(bpf_map)),
        max_entries_(bpf_map__max_entries(bpf_map))
  {
  }

  BpfMap(libbpf::bpf_map_type type,
         std::string name,
         uint32_t key_size,
         uint32_t value_size,
         uint32_t max_entries)
      : type_(type),
        name_(std::move(name)),
        key_size_(key_size),
        value_size_(value_size),
        max_entries_(max_entries)
  {
  }

  int fd() const;
  libbpf::bpf_map_type type() const;
  const std::string &bpf_name() const;
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
  libbpf::bpf_map_type type_;
  std::string name_;
  uint32_t key_size_;
  uint32_t value_size_;
  uint32_t max_entries_;
};

// Internal map types
enum class MapType {
  // Also update to_string
  PerfEvent,
  Join,
  Elapsed,
  Ringbuf,
  EventLossCounter,
  RecursionPrevention,
};

std::string to_string(MapType t);

// BPF maps do not accept "@" in name so we replace it by "AT_".
// The below two functions do the translations.
inline std::string bpf_map_name(std::string_view bpftrace_map_name)
{
  auto name = std::string{ bpftrace_map_name };
  if (name[0] == '@')
    name = "AT_" + name.substr(1);
  return name;
}

inline std::string bpftrace_map_name(std::string_view bpf_map_name)
{
  auto name = std::string{ bpf_map_name };
  if (name.starts_with("AT_"))
    name = "@" + name.substr(3);
  return name;
}

inline bool is_bpf_map_clearable(libbpf::bpf_map_type map_type)
{
  return map_type != libbpf::BPF_MAP_TYPE_ARRAY &&
         map_type != libbpf::BPF_MAP_TYPE_PERCPU_ARRAY;
}

libbpf::bpf_map_type get_bpf_map_type(const SizedType &val_type,
                                      const SizedType &key_type);
std::optional<libbpf::bpf_map_type> get_bpf_map_type(const std::string &name);
std::string get_bpf_map_type_str(libbpf::bpf_map_type map_type);
void add_bpf_map_types_hint(std::stringstream &hint);
bool is_array_map(const SizedType &val_type, const SizedType &key_type);
bool bpf_map_types_compatible(const SizedType &val_type,
                              const SizedType &key_type,
                              libbpf::bpf_map_type kind);

} // namespace bpftrace
