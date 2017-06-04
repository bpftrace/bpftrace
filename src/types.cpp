#include <iostream>
#include <sstream>

#include "types.h"

namespace ebpf {
namespace bpftrace {

std::string typestr(Type t)
{
  switch (t)
  {
    case Type::none:     return "none";     break;
    case Type::integer:  return "integer";  break;
    case Type::quantize: return "quantize"; break;
    case Type::count:    return "count";    break;
    default: abort();
  }
}

bpf_probe_attach_type attachtype(ProbeType t)
{
  switch (t)
  {
    case ProbeType::kprobe:    return BPF_PROBE_ENTRY;  break;
    case ProbeType::kretprobe: return BPF_PROBE_RETURN; break;
    default: abort();
  }
}

bpf_prog_type progtype(ProbeType t)
{
  switch (t)
  {
    case ProbeType::kprobe:    return BPF_PROG_TYPE_KPROBE; break;
    case ProbeType::kretprobe: return BPF_PROG_TYPE_KPROBE; break;
    default: abort();
  }
}

std::string argument_list(const std::vector<uint64_t> &items)
{
  return argument_list(items, items.size());
}

std::string argument_list(const std::vector<uint64_t> &items, size_t n)
{
  if (n == 0)
    return "";

  std::ostringstream list;
  list << "[";
  for (size_t i = 0; i < n-1; i++)
    list << items.at(i) << ", ";
  list << items.at(n-1) << "]";
  return list.str();
}

} // namespace bpftrace
} // namespace ebpf
