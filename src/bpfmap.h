#pragma once

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <optional>
#include <string>
#include <string_view>

#include "map_info.h"
#include "util/opaque.h"

namespace bpftrace {

class BpfMapError : public ErrorInfo<BpfMapError> {
public:
  static char ID;
  std::string name_;
  std::string op_;
  int errno_;

  BpfMapError(std::string name_, std::string op_, int errno_)
      : name_(std::move(name_)), op_(std::move(op_)), errno_(errno_)
  {
  }

  void log(llvm::raw_ostream &OS) const override
  {
    OS << "BPF map operation " << op_ << " failed: " << std::strerror(-errno_)
       << " [map = " << name_ << "]";
  }
};

using util::OpaqueValue;
using MapElements = std::vector<std::pair<OpaqueValue, OpaqueValue>>;
using HistogramMap = std::map<OpaqueValue, std::vector<uint64_t>>;
using TSeries = std::map<uint64_t, OpaqueValue>;
using TSeriesMap = std::map<OpaqueValue, TSeries>;

class BpfMap {
public:
  BpfMap(struct bpf_map *bpf_map)
      : bpf_map_(bpf_map),
        type_(bpf_map__type(bpf_map)),
        name_(bpf_map__name(bpf_map)),
        key_size_(bpf_map__key_size(bpf_map)),
        value_size_(bpf_map__value_size(bpf_map)),
        max_entries_(bpf_map__max_entries(bpf_map))
  {
  }

  BpfMap(bpf_map_type type,
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

  virtual ~BpfMap() = default;

  int fd() const;
  bpf_map_type type() const;
  const std::string &bpf_name() const;
  std::string name() const;
  uint32_t max_entries() const;

  bool is_stack_map() const;
  bool is_per_cpu_type() const;
  bool is_printable() const;

  std::vector<OpaqueValue> collect_keys() const;
  virtual Result<MapElements> collect_elements(int nvalues) const;
  virtual Result<HistogramMap> collect_histogram_data(const MapInfo &map_info,
                                                      int nvalues) const;
  virtual Result<TSeriesMap> collect_tseries_data(const MapInfo &map_info,
                                                  int nvalues) const;
  Result<> zero_out(int nvalues) const;
  Result<> clear() const;
  Result<> update_elem(const void *key, const void *value) const;
  Result<> lookup_elem(const void *key, void *value) const;
  Result<> resize(uint32_t new_size) const;

private:
  struct bpf_map *bpf_map_;
  bpf_map_type type_;
  std::string name_;
  uint32_t key_size_;
  uint32_t value_size_;
  uint32_t max_entries_;
};

// Internal map types
enum class MapType {
  // Also update to_string
  PerfEvent,
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

bpf_map_type get_bpf_map_type(const SizedType &val_type);
std::optional<bpf_map_type> get_bpf_map_type(const std::string &name);
std::string get_bpf_map_type_str(bpf_map_type map_type);
void add_bpf_map_types_hint(std::stringstream &hint);
bool bpf_map_types_compatible(const SizedType &val_type,
                              bpf_map_type kind);

} // namespace bpftrace
