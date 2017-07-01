#include <iostream>

#include "types.h"

namespace bpftrace {

std::ostream &operator<<(std::ostream &os, Type type)
{
  os << typestr(type);
  return os;
}

std::ostream &operator<<(std::ostream &os, MapKeyArgument arg)
{
  os << arg.type;
  return os;
}

bool MapKeyArgument::operator==(const MapKeyArgument &a) const
{
  return type == a.type && size == a.size;
}

std::string typestr(Type t)
{
  switch (t)
  {
    case Type::none:     return "none";     break;
    case Type::integer:  return "integer";  break;
    case Type::quantize: return "quantize"; break;
    case Type::count:    return "count";    break;
    case Type::stack:    return "stack";    break;
    case Type::ustack:   return "ustack";   break;
    default: abort();
  }
}

bpf_probe_attach_type attachtype(ProbeType t)
{
  switch (t)
  {
    case ProbeType::kprobe:    return BPF_PROBE_ENTRY;  break;
    case ProbeType::kretprobe: return BPF_PROBE_RETURN; break;
    case ProbeType::uprobe:    return BPF_PROBE_ENTRY;  break;
    case ProbeType::uretprobe: return BPF_PROBE_RETURN; break;
    default: abort();
  }
}

bpf_prog_type progtype(ProbeType t)
{
  switch (t)
  {
    case ProbeType::kprobe:    return BPF_PROG_TYPE_KPROBE; break;
    case ProbeType::kretprobe: return BPF_PROG_TYPE_KPROBE; break;
    case ProbeType::uprobe:    return BPF_PROG_TYPE_KPROBE; break;
    case ProbeType::uretprobe: return BPF_PROG_TYPE_KPROBE; break;
    default: abort();
  }
}

} // namespace bpftrace
