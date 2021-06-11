#include "imap.h"

#include <linux/version.h>

namespace bpftrace {

IMap::IMap(const std::string &name,
           const SizedType &type,
           const MapKey &key,
           int min,
           int max,
           int step,
           int max_entries __attribute__((unused)))
    : name_(name), type_(type), key_(key), lqmin(min), lqmax(max), lqstep(step)
{
  if (type.IsCountTy() && !key.args_.size())
  {
    map_type_ = BPF_MAP_TYPE_PERCPU_ARRAY;
  }
  else if ((type.IsHistTy() || type.IsLhistTy() || type.IsCountTy() ||
            type.IsSumTy() || type.IsMinTy() || type.IsMaxTy() ||
            type.IsAvgTy() || type.IsStatsTy()) &&
           (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)))
  {
    map_type_ = BPF_MAP_TYPE_PERCPU_HASH;
  }
  else
  {
    map_type_ = BPF_MAP_TYPE_HASH;
  }
}

IMap::IMap(const std::string &name,
           enum bpf_map_type type,
           int key_size __attribute__((unused)),
           int value_size __attribute__((unused)),
           int max_entries __attribute__((unused)),
           int flags __attribute__((unused)))
    : name_(name), map_type_(type)
{
}

IMap::IMap(const SizedType &type)
    : type_(type), map_type_(BPF_MAP_TYPE_STACK_TRACE)
{
  // This constructor should only be called with stack types
  assert(type.IsStack());
}

IMap::IMap(enum bpf_map_type map_type) : map_type_(map_type)
{
  // This constructor should only be called for perf events
  assert(map_type == BPF_MAP_TYPE_PERF_EVENT_ARRAY);
}

} // namespace bpftrace
