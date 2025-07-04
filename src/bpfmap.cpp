#include <sstream>
#include <unordered_map>

#include "bpfmap.h"
#include "log.h"
#include "util/exceptions.h"
#include "util/stats.h"

namespace bpftrace {
char BpfMapError::ID = 0;

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

bool BpfMap::is_printable() const
{
  // Internal maps are not printable
  return bpf_name().starts_with("AT_");
}

KeyVec BpfMap::collect_keys() const
{
  uint8_t *old_key = nullptr;
  auto key = KeyType(key_size_);

  // snapshot keys, then operate on them
  KeyVec keys;
  while (bpf_map_get_next_key(fd(), old_key, key.data()) == 0) {
    keys.push_back(key);
    old_key = key.data();
  }
  return keys;
}

Result<> BpfMap::zero_out(int nvalues) const
{
  auto keys = collect_keys();
  auto value_size = static_cast<size_t>(value_size_) *
                    static_cast<size_t>(nvalues);
  ValueType zero(value_size, 0);
  for (auto &k : keys) {
    int err = bpf_map_update_elem(fd(), k.data(), zero.data(), BPF_EXIST);

    if (err && err != -ENOENT) {
      return make_error<BpfMapError>(name_, "zero", err);
    }
  }
  return OK();
}

Result<> BpfMap::clear(int nvalues) const
{
  if (!is_bpf_map_clearable(type())) {
    return zero_out(nvalues);
  }
  auto keys = collect_keys();
  for (auto &k : keys) {
    int err = bpf_map_delete_elem(fd(), k.data());
    if (err && err != -ENOENT) {
      return make_error<BpfMapError>(name_, "clear", err);
    }
  }
  return OK();
}

Result<> BpfMap::update_elem(const void *key, const void *value) const
{
  auto err = bpf_map_update_elem(fd(), key, value, BPF_ANY);
  if (err != 0) {
    return make_error<BpfMapError>(name_, "update", err);
  }
  return OK();
}

Result<> BpfMap::lookup_elem(const void *key, void *value) const
{
  auto err = bpf_map_lookup_elem(fd(), key, value);
  if (err != 0) {
    return make_error<BpfMapError>(name_, "lookup", err);
  }
  return OK();
}

Result<MapElements> BpfMap::collect_elements(int nvalues) const
{
  uint8_t *old_key = nullptr;
  auto key = KeyType(key_size_);
  MapElements values_by_key;

  while (bpf_map_get_next_key(fd(), old_key, key.data()) == 0) {
    auto value = ValueType(static_cast<size_t>(value_size_) *
                           static_cast<size_t>(nvalues));
    int err = bpf_map_lookup_elem(fd(), key.data(), value.data());
    if (err == -ENOENT) {
      // key was removed by the eBPF program during bpf_map_get_next_key() and
      // bpf_map_lookup_elem(), let's skip this key
      continue;
    } else if (err) {
      return make_error<BpfMapError>(name_, "lookup", err);
    }

    values_by_key.emplace_back(key, value);

    old_key = key.data();
  }
  return values_by_key;
}

Result<HistogramMap> BpfMap::collect_histogram_data(const MapInfo &map_info,
                                                    int nvalues) const
{
  uint8_t *old_key = nullptr;
  auto key = KeyType(key_size_);

  HistogramMap values_by_key;

  while (bpf_map_get_next_key(fd(), old_key, key.data()) == 0) {
    auto key_prefix = KeyType(map_info.key_type.GetSize());
    auto bucket = util::read_data<BucketUnit>(key.data() +
                                              map_info.key_type.GetSize());

    std::ranges::copy(key.begin(),
                      key.begin() + map_info.key_type.GetSize(),
                      key_prefix.begin());

    auto value = ValueType(static_cast<size_t>(value_size_) *
                           static_cast<size_t>(nvalues));
    int err = bpf_map_lookup_elem(fd(), key.data(), value.data());
    if (err == -ENOENT) {
      // key was removed by the eBPF program during bpf_map_get_next_key() and
      // bpf_map_lookup_elem(), let's skip this key
      continue;
    } else if (err) {
      return make_error<BpfMapError>(name_, "lookup", err);
    }

    if (!values_by_key.contains(key_prefix)) {
      // New key - create a list of buckets for it
      if (map_info.value_type.IsHistTy())
        values_by_key[key_prefix] = BucketType(65 * 32);
      else
        values_by_key[key_prefix] = BucketType(1002);
    }
    values_by_key[key_prefix].at(
        bucket) = util::reduce_value<BucketUnit>(value, nvalues);

    old_key = key.data();
  }
  return values_by_key;
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
  if (scalar && !val_type.IsHistTy() && !val_type.IsLhistTy()) {
    return val_type.NeedsPercpuMap() ? libbpf::BPF_MAP_TYPE_PERCPU_ARRAY
                                     : libbpf::BPF_MAP_TYPE_ARRAY;
  } else {
    return val_type.NeedsPercpuMap() ? libbpf::BPF_MAP_TYPE_PERCPU_HASH
                                     : libbpf::BPF_MAP_TYPE_HASH;
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
