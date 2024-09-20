#include "bpfmap.h"

namespace bpftrace {

int BpfMap::fd() const
{
  return bpf_map__fd(bpf_map_);
}

libbpf::bpf_map_type BpfMap::type() const
{
  return type_;
}

cstring_view BpfMap::bpf_name() const
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
  return name().compare(0, 6, "stack_") == 0;
}

bool BpfMap::is_per_cpu_type() const
{
  return type() == libbpf::BPF_MAP_TYPE_PERCPU_HASH ||
         type() == libbpf::BPF_MAP_TYPE_PERCPU_ARRAY;
}

bool BpfMap::is_clearable() const
{
  return is_bpf_map_clearable(type());
}

bool BpfMap::is_printable() const
{
  // Internal maps are not printable
  return bpf_name().compare(0, 3, "AT_") == 0;
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
    case MapType::StrBuffer:
      return "str_buffer";
    case MapType::EventLossCounter:
      return "event_loss_counter";
    case MapType::RecursionPrevention:
      return "recursion_prevention";
  }
  return {}; // unreached
}

} // namespace bpftrace
