#include <iostream>
#include <algorithm>

#include "types.h"

namespace bpftrace {

std::ostream &operator<<(std::ostream &os, Type type)
{
  os << typestr(type);
  return os;
}

std::ostream &operator<<(std::ostream &os, const SizedType &type)
{
  if (type.type == Type::cast)
  {
    os << type.cast_type;
  }
  else if (type.type == Type::ctx)
  {
    os << "(ctx) " << type.cast_type;
  }
  else if (type.type == Type::integer)
  {
    os << (type.is_signed ? "" : "unsigned ") << "int" << 8*type.size;
  }
  else if (type.type == Type::array)
  {
    os << (type.is_signed ? "" : "unsigned ") << "int" << 8 * type.pointee_size;
    os << "[" << type.size << "]";
  }
  else if (type.type == Type::string || type.type == Type::buffer)
  {
    os << type.type << "[" << type.size << "]";
  }
  else
  {
    os << type.type;
  }

  if (type.is_pointer)
    os << "*";

  return os;
}

bool SizedType::IsEqual(const SizedType &t) const
{
  return type == t.type && size == t.size && is_signed == t.is_signed;
}

bool SizedType::operator!=(const SizedType &t) const
{
  return !IsEqual(t);
}

bool SizedType::operator==(const SizedType &t) const
{
  return IsEqual(t);
}

bool SizedType::IsArray() const
{
  return type == Type::array || type == Type::string || type == Type::usym ||
         type == Type::inet || type == Type::buffer ||
         ((type == Type::cast || type == Type::ctx) && !is_pointer);
}

bool SizedType::IsStack() const
{
  return type == Type::ustack || type == Type::kstack;
}

std::string typestr(Type t)
{
  switch (t)
  {
    // clang-format off
    case Type::none:     return "none";     break;
    case Type::integer:  return "integer";  break;
    case Type::hist:     return "hist";     break;
    case Type::lhist:    return "lhist";    break;
    case Type::count:    return "count";    break;
    case Type::sum:      return "sum";      break;
    case Type::min:      return "min";      break;
    case Type::max:      return "max";      break;
    case Type::avg:      return "avg";      break;
    case Type::stats:    return "stats";    break;
    case Type::kstack:   return "kstack";   break;
    case Type::ustack:   return "ustack";   break;
    case Type::string:   return "string";   break;
    case Type::ksym:     return "ksym";     break;
    case Type::usym:     return "usym";     break;
    case Type::cast:     return "cast";     break;
    case Type::join:     return "join";     break;
    case Type::probe:    return "probe";    break;
    case Type::username: return "username"; break;
    case Type::inet:     return "inet";     break;
    case Type::stack_mode:return "stack mode";break;
    case Type::array:    return "array";    break;
    case Type::ctx:      return "ctx";      break;
    case Type::buffer:   return "buffer";   break;
    // clang-format on
    default:
      std::cerr << "call or probe type not found" << std::endl;
      abort();
  }
}

ProbeType probetype(const std::string &probeName)
{
  ProbeType retType = ProbeType::invalid;

  auto v = std::find_if(PROBE_LIST.begin(), PROBE_LIST.end(),
                          [&probeName] (const ProbeItem& p) {
                            return (p.name == probeName ||
                                   p.abbr == probeName);
                         });

  if (v != PROBE_LIST.end())
    retType =  v->type;

  return retType;
}

std::string probetypeName(const std::string &probeName)
{
  std::string res = probeName;

  auto v = std::find_if(PROBE_LIST.begin(), PROBE_LIST.end(),
                          [&probeName] (const ProbeItem& p) {
                            return (p.name == probeName ||
                                    p.abbr == probeName);
                          });

  if (v != PROBE_LIST.end())
    res = v->name;

  return res;
}

std::string probetypeName(ProbeType t)
{
   switch (t)
  {
    case ProbeType::invalid:     return "invalid";     break;
    case ProbeType::kprobe:      return "kprobe";      break;
    case ProbeType::kretprobe:   return "kretprobe";   break;
    case ProbeType::uprobe:      return "uprobe";      break;
    case ProbeType::uretprobe:   return "uretprobe";   break;
    case ProbeType::usdt:        return "usdt";        break;
    case ProbeType::tracepoint:  return "tracepoint";  break;
    case ProbeType::profile:     return "profile";     break;
    case ProbeType::interval:    return "interval";    break;
    case ProbeType::software:    return "software";    break;
    case ProbeType::hardware:    return "hardware";    break;
    case ProbeType::watchpoint:  return "watchpoint";  break;
    case ProbeType::kfunc:       return "kfunc";       break;
    case ProbeType::kretfunc:    return "kretfunc";    break;
    default:
      std::cerr << "probe type not found" << std::endl;
      abort();
  }
}

uint64_t asyncactionint(AsyncAction a)
{
  return (uint64_t)a;
}

} // namespace bpftrace
