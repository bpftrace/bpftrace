#include "bpfmap.h"

namespace bpftrace {

libbpf::bpf_map_type BpfMap::type() const
{
  return static_cast<libbpf::bpf_map_type>(bpf_map__type(bpf_map_));
}

std::string BpfMap::bpf_name() const
{
  return bpf_map__name(bpf_map_);
}

std::string BpfMap::name() const
{
  return bpftrace_map_name(bpf_name());
}

uint32_t BpfMap::key_size() const
{
  return bpf_map__key_size(bpf_map_);
}

uint32_t BpfMap::value_size() const
{
  return bpf_map__value_size(bpf_map_);
}

uint32_t BpfMap::max_entries() const
{
  return bpf_map__max_entries(bpf_map_);
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
    case MapType::MappedPrintfData:
      return "mapped_printf_data";
    case MapType::Ringbuf:
      return "ringbuf";
    case MapType::RingbufLossCounter:
      return "ringbuf_loss_counter";
  }
  return {}; // unreached
}

} // namespace bpftrace
