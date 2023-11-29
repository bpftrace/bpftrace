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

} // namespace bpftrace
