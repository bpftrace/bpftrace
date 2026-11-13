#include <algorithm>
#include <sstream>
#include <unordered_map>

#include "bpfmap.h"
#include "util/stats.h"
#include "util/tseries.h"

namespace bpftrace {
char BpfMapError::ID = 0;

namespace {

// Each batch syscall requests up to MAP_BATCH_SIZE elements, fewer if the
// buffers would exceed MAP_BATCH_BYTES. The buffers grow if a single hash
// bucket holds more elements than that.
constexpr uint32_t MAP_BATCH_SIZE = 1024;
constexpr size_t MAP_BATCH_BYTES = 1024 * 1024;

// The kernel returns ENOTSUPP for map types without batch operations. It is
// not exported to userspace, so define it here.
constexpr int KERNEL_ENOTSUPP = 524;

bool batch_op_unsupported(int err)
{
  // Kernels that don't know a batch command return EINVAL for it.
  return err == -KERNEL_ENOTSUPP || err == -EOPNOTSUPP || err == -EINVAL;
}

} // namespace

Result<bool> batch_walk_map(const std::string &map_name,
                            const std::string &op_name,
                            uint32_t key_size,
                            size_t value_size,
                            const MapBatchOp &op,
                            const MapElementCallback &fn)
{
  auto elem_size = std::max<size_t>(key_size + value_size, 1);
  auto batch_size = static_cast<uint32_t>(
      std::clamp<size_t>(MAP_BATCH_BYTES / elem_size, 1, MAP_BATCH_SIZE));
  std::vector<char> keys(static_cast<size_t>(batch_size) * key_size);
  std::vector<char> values(static_cast<size_t>(batch_size) * value_size);
  // The batch position is opaque: hash maps keep a 32-bit bucket index in it
  // and other map types keep a key, so make room for either.
  std::vector<char> position(std::max<size_t>(key_size, sizeof(uint64_t)));
  bool started = false;

  while (true) {
    uint32_t count = batch_size;
    int err = op(started ? position.data() : nullptr,
                 position.data(),
                 keys.data(),
                 values.data(),
                 &count);
    if (err == -ENOSPC && count == 0 && batch_size <= UINT32_MAX / 2) {
      // A single hash bucket holds more elements than fit into the buffers.
      // Grow them and retry from the same position.
      batch_size *= 2;
      keys.resize(static_cast<size_t>(batch_size) * key_size);
      values.resize(static_cast<size_t>(batch_size) * value_size);
      continue;
    }
    if (err && err != -ENOENT) {
      if (!started && batch_op_unsupported(err)) {
        return false;
      }
      return make_error<BpfMapError>(map_name, op_name, err);
    }

    if (fn) {
      for (size_t i = 0; i < count; i++) {
        fn(OpaqueValue::from(keys.data() + (i * key_size), key_size),
           OpaqueValue::from(values.data() + (i * value_size), value_size));
      }
    }

    // ENOENT means that this batch held the last elements of the map.
    if (err == -ENOENT) {
      return true;
    }
    started = true;
  }
}

const std::unordered_map<std::string, bpf_map_type> BPF_MAP_TYPES = {
  { "hash", BPF_MAP_TYPE_HASH },
  { "lruhash", BPF_MAP_TYPE_LRU_HASH },
  { "percpuhash", BPF_MAP_TYPE_PERCPU_HASH },
  { "percpulruhash", BPF_MAP_TYPE_LRU_PERCPU_HASH }
};

int BpfMap::fd() const
{
  return bpf_map__fd(bpf_map_);
}

bpf_map_type BpfMap::type() const
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
  return type() == BPF_MAP_TYPE_PERCPU_HASH ||
         type() == BPF_MAP_TYPE_LRU_PERCPU_HASH;
}

bool BpfMap::is_printable() const
{
  // Internal maps are not printable
  return bpf_name().starts_with("AT_");
}

std::vector<OpaqueValue> BpfMap::collect_keys() const
{
  const void *last_key = nullptr;
  std::vector<OpaqueValue> keys;
  while (true) {
    int rc = 0;
    auto key = OpaqueValue::alloc(key_size_, [&](void *data) {
      rc = bpf_map_get_next_key(fd(), last_key, data);
    });
    if (rc != 0) {
      break;
    }
    last_key = keys.emplace_back(std::move(key)).data();
  }
  return keys;
}

Result<> BpfMap::zero_out(int nvalues) const
{
  auto keys = collect_keys();
  auto value_size = static_cast<size_t>(value_size_) *
                    static_cast<size_t>(nvalues);
  auto zero = OpaqueValue::alloc(value_size, [&](void *data) {
    memset(data, 0, value_size);
  });
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
  // BPF_MAP_LOOKUP_AND_DELETE_BATCH removes many elements per syscall. It also
  // copies out the values, which are discarded.
  auto value_size = static_cast<size_t>(value_size_) *
                    static_cast<size_t>(nvalues);
  auto batched = batch_walk_map(
      name_,
      "clear",
      key_size_,
      value_size,
      [&](void *in_batch,
          void *out_batch,
          void *keys,
          void *values,
          uint32_t *count) {
        return bpf_map_lookup_and_delete_batch(
            fd(), in_batch, out_batch, keys, values, count, nullptr);
      },
      nullptr);
  if (!batched) {
    return batched.takeError();
  }
  if (*batched) {
    return OK();
  }

  // Batch operations are not supported, delete the keys one by one.
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

Result<> BpfMap::resize(uint32_t new_size) const
{
  auto err = bpf_map__set_max_entries(bpf_map_, new_size);
  if (err != 0) {
    return make_error<BpfMapError>(name_, "resize", err);
  }
  return OK();
}

Result<> BpfMap::for_each_elem(int nvalues, const MapElementCallback &fn) const
{
  auto value_size = static_cast<size_t>(value_size_) *
                    static_cast<size_t>(nvalues);
  auto batched = batch_walk_map(
      name_,
      "lookup",
      key_size_,
      value_size,
      [&](void *in_batch,
          void *out_batch,
          void *keys,
          void *values,
          uint32_t *count) {
        return bpf_map_lookup_batch(
            fd(), in_batch, out_batch, keys, values, count, nullptr);
      },
      fn);
  if (!batched) {
    return batched.takeError();
  }
  if (*batched) {
    return OK();
  }

  // Batch operations are not supported, look up the keys one by one.
  auto keys = collect_keys();
  for (auto &key : keys) {
    int err = 0;
    auto value = OpaqueValue::alloc(value_size, [&](void *data) {
      err = bpf_map_lookup_elem(fd(), key.data(), data);
    });
    if (err == -ENOENT) {
      // key was removed by the eBPF program during bpf_map_get_next_key() and
      // bpf_map_lookup_elem(), let's skip this key.
      continue;
    } else if (err) {
      return make_error<BpfMapError>(name_, "lookup", err);
    }
    fn(std::move(key), std::move(value));
  }
  return OK();
}

Result<MapElements> BpfMap::collect_elements(int nvalues) const
{
  MapElements values_by_key;
  auto ok = for_each_elem(nvalues, [&](OpaqueValue key, OpaqueValue value) {
    values_by_key.emplace_back(std::move(key), std::move(value));
  });
  if (!ok) {
    return ok.takeError();
  }
  return values_by_key;
}

Result<HistogramMap> BpfMap::collect_histogram_data(const MapInfo &map_info,
                                                    int nvalues) const
{
  HistogramMap values_by_key;
  auto ok = for_each_elem(nvalues, [&](OpaqueValue key, OpaqueValue value) {
    auto prefix = key.slice(0, map_info.key_type.GetSize());
    auto bucket = key.slice(map_info.key_type.GetSize(), sizeof(uint64_t));
    if (!values_by_key.contains(prefix)) {
      // New key - create a list of buckets for it
      if (map_info.value_type.IsHistTy())
        values_by_key[prefix].resize(65 * 32, 0);
      else
        values_by_key[prefix].resize(1002, 0);
    }
    auto idx = bucket.bitcast<uint64_t>();
    values_by_key[prefix].at(idx) = util::reduce_value<uint64_t>(value);
  });
  if (!ok) {
    return ok.takeError();
  }
  return values_by_key;
}

Result<TSeriesMap> BpfMap::collect_tseries_data(const MapInfo &map_info,
                                                int nvalues) const
{
  TSeriesMap values_by_key;

  const auto &tseries_args = std::get<TSeriesArgs>(map_info.detail);
  auto ok = for_each_elem(nvalues, [&](OpaqueValue key, OpaqueValue value) {
    auto prefix = key.slice(0, map_info.key_type.GetSize());
    auto bucket = key.slice(map_info.key_type.GetSize(), sizeof(uint64_t));
    auto tseries = values_by_key.try_emplace(prefix).first;
    auto [epoch, v] = util::reduce_tseries_value(value,
                                                 tseries_args.value_type,
                                                 tseries_args.agg);
    tseries->second.emplace(epoch, std::move(v));
  });
  if (!ok) {
    return ok.takeError();
  }
  return values_by_key;
}

std::string to_string(MapType t)
{
  switch (t) {
    case MapType::PerfEvent:
      return "perf_event";
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

bpf_map_type get_bpf_map_type(const SizedType &val_type)
{
  if (val_type.NeedsPercpuMap()) {
    return BPF_MAP_TYPE_PERCPU_HASH;
  } else {
    return BPF_MAP_TYPE_HASH;
  }
}

std::optional<bpf_map_type> get_bpf_map_type(const std::string &name)
{
  auto found = BPF_MAP_TYPES.find(name);
  if (found == BPF_MAP_TYPES.end()) {
    return std::nullopt;
  }
  return found->second;
}

std::string get_bpf_map_type_str(bpf_map_type map_type)
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

bool bpf_map_types_compatible(const SizedType &val_type, bpf_map_type kind)
{
  auto kind_from_stype = get_bpf_map_type(val_type);
  if (kind_from_stype == kind) {
    return true;
  }
  if ((kind_from_stype == BPF_MAP_TYPE_HASH ||
       kind_from_stype == BPF_MAP_TYPE_LRU_HASH) &&
      (kind == BPF_MAP_TYPE_HASH || kind == BPF_MAP_TYPE_LRU_HASH)) {
    return true;
  }

  if ((kind_from_stype == BPF_MAP_TYPE_PERCPU_HASH ||
       kind_from_stype == BPF_MAP_TYPE_LRU_PERCPU_HASH) &&
      (kind == BPF_MAP_TYPE_PERCPU_HASH ||
       kind == BPF_MAP_TYPE_LRU_PERCPU_HASH)) {
    return true;
  }

  return false;
}

} // namespace bpftrace
