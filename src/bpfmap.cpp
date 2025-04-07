#include <sstream>
#include <unordered_map>

#include "bpfmap.h"

namespace bpftrace {

const std::unordered_map<std::string, libbpf::bpf_map_type> BPF_MAP_TYPES = {
  { "hash", libbpf::BPF_MAP_TYPE_HASH },
  { "lruhash", libbpf::BPF_MAP_TYPE_LRU_HASH },
  { "percpuhash", libbpf::BPF_MAP_TYPE_PERCPU_HASH },
  { "percpuarray", libbpf::BPF_MAP_TYPE_PERCPU_ARRAY },
  { "percpulruhash", libbpf::BPF_MAP_TYPE_LRU_PERCPU_HASH }
};

int BpfMap::fd() const
{
  return bpf_map__fd(bpf_map_);
}

libbpf::bpf_map_type BpfMap::type() const
{
  return type_;
}

const std::string &BpfMap::bpf_name() const
{
  return name_;
}

std::string BpfMap::name() const
{
  return bpftrace_map_name(bpf_name());
}

uint32_t BpfMap::key_size() const
{
  return key_size_;
}

uint32_t BpfMap::value_size() const
{
  return value_size_;
}

uint32_t BpfMap::max_entries() const
{
  return max_entries_;
}

bool BpfMap::is_stack_map() const
{
  return name().starts_with("stack_");
}

bool BpfMap::is_per_cpu_type() const
{
  return type() == libbpf::BPF_MAP_TYPE_PERCPU_HASH ||
         type() == libbpf::BPF_MAP_TYPE_PERCPU_ARRAY ||
         type() == libbpf::BPF_MAP_TYPE_LRU_PERCPU_HASH;
}

bool BpfMap::is_clearable() const
{
  return is_bpf_map_clearable(type());
}

bool BpfMap::is_printable() const
{
  // Internal maps are not printable
  return bpf_name().starts_with("AT_");
}

std::string to_string(MapType t)
{
  switch (t) {
    case MapType::PerfEvent:
      return "perf_event";
    case MapType::Join:
      return "join";
    case MapType::Elapsed:
      return "elapsed";
    case MapType::Ringbuf:
      return "ringbuf";
    case MapType::EventLossCounter:
      return "event_loss_counter";
    case MapType::RecursionPrevention:
      return "recursion_prevention";
  }
  return {}; // unreached
}

libbpf::bpf_map_type get_bpf_map_type(const SizedType &val_type, bool scalar)
{
  if (val_type.IsCountTy() && scalar) {
    return libbpf::BPF_MAP_TYPE_PERCPU_ARRAY;
  } else if (val_type.NeedsPercpuMap()) {
    return libbpf::BPF_MAP_TYPE_PERCPU_HASH;
  } else {
    return libbpf::BPF_MAP_TYPE_HASH;
  }
}

std::optional<libbpf::bpf_map_type> get_bpf_map_type(const std::string &name)
{
  auto found = BPF_MAP_TYPES.find(name);
  if (found == BPF_MAP_TYPES.end()) {
    return std::nullopt;
  }
  return found->second;
}

std::string get_bpf_map_type_str(libbpf::bpf_map_type map_type)
{
  for (const auto &pair : BPF_MAP_TYPES) {
    if (pair.second == map_type) {
      return pair.first;
    }
  }
  return "unknown";
}

void add_bpf_map_types_hint(std::stringstream &hint)
{
  hint << "Valid map types: ";
  int num_types = BPF_MAP_TYPES.size();
  for (const auto &bpf_type : BPF_MAP_TYPES) {
    hint << bpf_type.first;
    num_types--;
    if (num_types != 0) {
      hint << ", ";
    }
  }
}

bool is_array_map(const SizedType &val_type, bool scalar)
{
  auto map_type = get_bpf_map_type(val_type, scalar);
  return map_type == libbpf::BPF_MAP_TYPE_ARRAY ||
         map_type == libbpf::BPF_MAP_TYPE_PERCPU_ARRAY;
}

bool bpf_map_types_compatible(const SizedType &val_type,
                              bool scalar,
                              libbpf::bpf_map_type kind)
{
  auto kind_from_stype = get_bpf_map_type(val_type, scalar);
  if (kind_from_stype == kind) {
    return true;
  }
  if ((kind_from_stype == libbpf::BPF_MAP_TYPE_HASH ||
       kind_from_stype == libbpf::BPF_MAP_TYPE_LRU_HASH) &&
      (kind == libbpf::BPF_MAP_TYPE_HASH ||
       kind == libbpf::BPF_MAP_TYPE_LRU_HASH)) {
    return true;
  }

  if ((kind_from_stype == libbpf::BPF_MAP_TYPE_PERCPU_HASH ||
       kind_from_stype == libbpf::BPF_MAP_TYPE_LRU_PERCPU_HASH) &&
      (kind == libbpf::BPF_MAP_TYPE_PERCPU_HASH ||
       kind == libbpf::BPF_MAP_TYPE_LRU_PERCPU_HASH)) {
    return true;
  }

  // This doesn't work the opposite way
  if (kind == libbpf::BPF_MAP_TYPE_PERCPU_HASH &&
      kind_from_stype == libbpf::BPF_MAP_TYPE_PERCPU_ARRAY) {
    return true;
  }

  return false;
}

} // namespace bpftrace
