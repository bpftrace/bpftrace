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
    case Type::stack:    return "stack";    break;
    case Type::ustack:   return "ustack";   break;
    default: abort();
  }
}

} // namespace bpftrace
