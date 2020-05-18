#include <algorithm>
#include <cassert>
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
  if (type.IsCastTy())
  {
    os << type.cast_type;
  }
  else if (type.IsCtxTy())
  {
    os << "(ctx) " << type.cast_type;
  }
  else if (type.IsIntTy())
  {
    os << (type.is_signed ? "" : "unsigned ") << "int" << 8*type.size;
  }
  else if (type.IsArrayTy())
  {
    os << (type.is_signed ? "" : "unsigned ") << "int" << 8 * type.pointee_size;
    os << "[" << type.size << "]";
  }
  else if (type.IsStringTy() || type.IsBufferTy())
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

// Type wrappers
SizedType CreateInteger(size_t bits, bool is_signed)
{
  // Zero sized integers are not usually valid. However, during semantic
  // analysis when we're inferring types, the first pass may not have
  // enough information to figure out the exact size of the integer. Later
  // passes infer the exact size.
  assert(bits == 0 || bits == 8 || bits == 16 || bits == 32 || bits == 64);
  return SizedType(Type::integer, bits / 8, is_signed);
}

SizedType CreateInt(size_t bits)
{
  return CreateInteger(bits, true);
};

SizedType CreateUInt(size_t bits)
{
  return CreateInteger(bits, false);
}

SizedType CreateInt8()
{
  return CreateInt(8);
}

SizedType CreateInt16()
{
  return CreateInt(16);
}

SizedType CreateInt32()
{
  return CreateInt(32);
}

SizedType CreateInt64()
{
  return CreateInt(64);
}

SizedType CreateUInt8()
{
  return CreateUInt(8);
}

SizedType CreateUInt16()
{
  return CreateUInt(16);
}

SizedType CreateUInt32()
{
  return CreateUInt(32);
}

SizedType CreateUInt64()
{
  return CreateUInt(64);
}

SizedType CreateString(size_t size)
{
  return SizedType(Type::string, size);
}

SizedType CreateNone()
{
  return SizedType(Type::none, 0);
}

SizedType CreateStackMode()
{
  return SizedType(Type::stack_mode, 0);
}

SizedType CreateCast(size_t size, std::string name)
{
  assert(size % 8 == 0);
  return SizedType(Type::cast, size / 8, name);
}

SizedType CreateCTX(size_t size, std::string name)
{
  return SizedType(Type::ctx, size, name);
}

SizedType CreateArray(size_t num_elem,
                      Type elem_type,
                      size_t elem_size,
                      bool elem_is_signed)
{
  auto ty = SizedType(Type::array, num_elem, elem_is_signed);
  ty.elem_type = elem_type;
  ty.pointee_size = elem_size;
  return ty;
}

SizedType CreateStack(bool kernel, StackType stack)
{
  auto st = SizedType(kernel ? Type::kstack : Type::ustack, 8);
  st.stack_type = stack;
  return st;
}

SizedType CreateMin(bool is_signed)
{
  return SizedType(Type::min, 8, is_signed);
}

SizedType CreateMax(bool is_signed)
{
  return SizedType(Type::max, 8, is_signed);
}

SizedType CreateSum(bool is_signed)
{
  return SizedType(Type::sum, 8, is_signed);
}

SizedType CreateCount(bool is_signed)
{
  return SizedType(Type::count, 8, is_signed);
}

SizedType CreateAvg(bool is_signed)
{
  return SizedType(Type::avg, 8, is_signed);
}

SizedType CreateStats(bool is_signed)
{
  return SizedType(Type::stats, 8, is_signed);
}

SizedType CreateProbe()
{
  return SizedType(Type::probe, 8);
}

SizedType CreateUsername()
{
  return SizedType(Type::username, 8);
}

SizedType CreateInet(size_t size)
{
  auto st = SizedType(Type::inet, size);
  st.is_internal = true;
  return st;
}

SizedType CreateLhist()
{
  return SizedType(Type::lhist, 8);
}

SizedType CreateHist()
{
  return SizedType(Type::hist, 8);
}

SizedType CreateUSym()
{
  return SizedType(Type::usym, 16);
}

SizedType CreateKSym()
{
  return SizedType(Type::ksym, 8);
}

SizedType CreateJoin(size_t argnum, size_t argsize)
{
  return SizedType(Type::join, 8 + 8 + argnum * argsize);
}

SizedType CreateBuffer(size_t size)
{
  return SizedType(Type::buffer, size);
}

bool SizedType::IsSigned(void) const
{
  return is_signed;
}

} // namespace bpftrace
