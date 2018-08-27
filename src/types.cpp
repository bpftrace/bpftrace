#include <iostream>

#include "types.h"

namespace bpftrace {

std::ostream &operator<<(std::ostream &os, Type type)
{
  os << typestr(type);
  return os;
}

std::ostream &operator<<(std::ostream &os, const SizedType &type)
{
  os << type.type;
  return os;
}

bool SizedType::operator==(const SizedType &t) const
{
  return type == t.type && size == t.size;
}

std::string typestr(Type t)
{
  switch (t)
  {
    case Type::none:     return "none";     break;
    case Type::integer:  return "integer";  break;
    case Type::quantize: return "quantize"; break;
    case Type::count:    return "count";    break;
    case Type::sum:      return "sum";      break;
    case Type::min:      return "min";      break;
    case Type::max:      return "max";      break;
    case Type::avg:      return "avg";      break;
    case Type::stats:    return "stats";    break;
    case Type::stack:    return "stack";    break;
    case Type::ustack:   return "ustack";   break;
    case Type::string:   return "string";   break;
    case Type::sym:      return "sym";      break;
    case Type::usym:     return "usym";     break;
    case Type::cast:     return "cast";     break;
    default: abort();
  }
}

ProbeType probetype(const std::string &type)
{
  if (type == "kprobe")
    return ProbeType::kprobe;
  else if (type == "kretprobe")
    return ProbeType::kretprobe;
  else if (type == "uprobe")
    return ProbeType::uprobe;
  else if (type == "uretprobe")
    return ProbeType::uretprobe;
  else if (type == "BEGIN")
    return ProbeType::uprobe;
  else if (type == "END")
    return ProbeType::uprobe;
  else if (type == "tracepoint")
    return ProbeType::tracepoint;
  else if (type == "profile")
    return ProbeType::profile;
  else if (type == "interval")
    return ProbeType::interval;
  else if (type == "software")
    return ProbeType::software;
  else if (type == "hardware")
    return ProbeType::hardware;
  abort();
}

uint64_t asyncactionint(AsyncAction a)
{
  return (uint64_t)a;
}

} // namespace bpftrace
