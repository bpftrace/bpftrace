#include <algorithm>
#include <cassert>
#include <iostream>

#include "bpftrace.h"
#include "log.h"
#include "struct.h"
#include "types.h"

namespace bpftrace {

std::ostream &operator<<(std::ostream &os, Type type)
{
  os << typestr(type);
  return os;
}

std::ostream &operator<<(std::ostream &os, AddrSpace as)
{
  os << addrspacestr(as);
  return os;
}

std::ostream &operator<<(std::ostream &os, ProbeType type)
{
  os << probetypeName(type);
  return os;
}

std::ostream &operator<<(std::ostream &os, const SizedType &type)
{
  if (type.IsRecordTy())
  {
    os << type.GetName();
  }
  else if (type.IsPtrTy())
  {
    if (type.IsCtxAccess())
      os << "(ctx) ";
    os << *type.GetPointeeTy() << " *";
  }
  else if (type.IsIntTy())
  {
    os << (type.is_signed_ ? "" : "unsigned ") << "int" << 8 * type.GetSize();
  }
  else if (type.IsArrayTy())
  {
    os << *type.GetElementTy() << "[" << type.GetNumElements() << "]";
  }
  else if (type.IsStringTy() || type.IsBufferTy())
  {
    os << type.type << "[" << type.GetSize() << "]";
  }
  else if (type.IsTupleTy())
  {
    os << "(";
    size_t n = type.GetFieldCount();
    for (size_t i = 0; i < n; ++i)
    {
      os << type.GetField(i).type;
      if (i != n - 1)
        os << ",";
    }
    os << ")";
  }
  else
  {
    os << type.type;
  }

  return os;
}

bool SizedType::IsSameType(const SizedType &t) const
{
  if (t.type != type)
    return false;

  if (IsRecordTy())
    return t.GetName() == GetName();

  if (IsPtrTy() && t.IsPtrTy())
    return GetPointeeTy()->IsSameType(*t.GetPointeeTy());

  return type == t.type;
}

bool SizedType::IsEqual(const SizedType &t) const
{
  if (t.type != type)
    return false;

  if (IsRecordTy())
    return t.GetName() == GetName() && t.GetSize() == GetSize();

  if (IsPtrTy())
    return *t.GetPointeeTy() == *GetPointeeTy();

  if (IsArrayTy())
    return t.GetNumElements() == GetNumElements() &&
           *t.GetElementTy() == *GetElementTy();

  if (IsTupleTy())
    return *t.GetStruct().lock() == *GetStruct().lock();

  return type == t.type && GetSize() == t.GetSize() &&
         is_signed_ == t.is_signed_;
}

bool SizedType::operator!=(const SizedType &t) const
{
  return !IsEqual(t);
}

bool SizedType::operator==(const SizedType &t) const
{
  return IsEqual(t);
}

bool SizedType::IsByteArray() const
{
  return type == Type::string || type == Type::usym || type == Type::inet ||
         type == Type::buffer || type == Type::timestamp ||
         type == Type::mac_address;
}

bool SizedType::IsAggregate() const
{
  return IsArrayTy() || IsByteArray() || IsTupleTy() || IsRecordTy();
}

bool SizedType::IsStack() const
{
  return type == Type::ustack || type == Type::kstack;
}

std::string addrspacestr(AddrSpace as)
{
  switch (as)
  {
    case AddrSpace::kernel:
      return "kernel";
      break;
    case AddrSpace::user:
      return "user";
      break;
    case AddrSpace::none:
      return "none";
      break;
  }

  return {}; // unreached
}

std::string typestr(Type t)
{
  switch (t)
  {
    // clang-format off
    case Type::none:     return "none";     break;
    case Type::integer:  return "integer";  break;
    case Type::pointer:  return "pointer";  break;
    case Type::record:   return "record";   break;
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
    case Type::probe:    return "probe";    break;
    case Type::username: return "username"; break;
    case Type::inet:     return "inet";     break;
    case Type::stack_mode:return "stack mode";break;
    case Type::array:    return "array";    break;
    case Type::buffer:   return "buffer";   break;
    case Type::tuple:    return "tuple";    break;
    case Type::timestamp:return "timestamp";break;
    case Type::mac_address: return "mac_address"; break;
      // clang-format on
  }

  return {}; // unreached
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
    case ProbeType::asyncwatchpoint:
      return "asyncwatchpoint";
      break;
    case ProbeType::kfunc:       return "kfunc";       break;
    case ProbeType::kretfunc:    return "kretfunc";    break;
    case ProbeType::iter:
      return "iter";
      break;
  }

  return {}; // unreached
}

bool is_userspace_probe(const ProbeType &probe_type)
{
  return probe_type == ProbeType::uprobe ||
         probe_type == ProbeType::uretprobe || probe_type == ProbeType::usdt;
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
  assert(bits == 0 || bits == 1 || bits == 8 || bits == 16 || bits == 32 ||
         bits == 64);
  auto t = SizedType(Type::integer, bits / 8, is_signed);
  t.size_bits_ = bits;
  return t;
}

SizedType CreateBool(void)
{
  return CreateInteger(1, false);
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

SizedType CreateArray(size_t num_elements, const SizedType &element_type)
{
  size_t size = num_elements * element_type.GetSize();
  auto ty = SizedType(Type::array, size);
  ty.num_elements_ = num_elements;
  ty.element_type_ = std::make_shared<SizedType>(element_type);
  return ty;
}

SizedType CreatePointer(const SizedType &pointee_type, AddrSpace as)
{
  // Pointer itself is always an uint64
  auto ty = SizedType(Type::pointer, 8);
  ty.element_type_ = std::make_shared<SizedType>(pointee_type);
  ty.SetAS(as);
  return ty;
}

SizedType CreateRecord(const std::string &name, std::weak_ptr<Struct> record)
{
  auto ty = SizedType(Type::record, record.expired() ? 0 : record.lock()->size);
  ty.name_ = name;
  ty.inner_struct_ = record;
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

SizedType CreateBuffer(size_t size)
{
  return SizedType(Type::buffer, size);
}

SizedType CreateTimestamp()
{
  return SizedType(Type::timestamp, 16);
}

SizedType CreateTuple(std::weak_ptr<Struct> tuple)
{
  auto s = SizedType(Type::tuple, tuple.lock()->size);
  s.inner_struct_ = tuple;
  return s;
}

SizedType CreateMacAddress()
{
  auto st = SizedType(Type::mac_address, 6);
  st.is_internal = true;
  return st;
}

bool SizedType::IsSigned(void) const
{
  return is_signed_;
}

std::vector<Field> &SizedType::GetFields() const
{
  assert(IsTupleTy() || IsRecordTy());
  return inner_struct_.lock()->fields;
}

Field &SizedType::GetField(ssize_t n) const
{
  assert(IsTupleTy() || IsRecordTy());
  if (n >= GetFieldCount())
    throw std::runtime_error("Getfield(): out of bound");
  return inner_struct_.lock()->fields[n];
}

ssize_t SizedType::GetFieldCount() const
{
  assert(IsTupleTy() || IsRecordTy());
  return inner_struct_.lock()->fields.size();
}

void SizedType::DumpStructure(std::ostream &os)
{
  assert(IsTupleTy());
  if (IsTupleTy())
    os << "tuple";
  else
    os << "struct";
  return inner_struct_.lock()->Dump(os);
}

ssize_t SizedType::GetAlignment() const
{
  if (IsStringTy())
    return 1;

  if (IsTupleTy() || IsRecordTy())
    return inner_struct_.lock()->align;

  if (GetSize() <= 2)
    return GetSize();
  else if (IsArrayTy())
    return element_type_->GetAlignment();
  else if (IsByteArray() || GetSize() <= 4)
    return 4;
  else
    return 8;
}

bool SizedType::HasField(const std::string &name) const
{
  assert(IsRecordTy());
  return inner_struct_.lock()->HasField(name);
}

const Field &SizedType::GetField(const std::string &name) const
{
  assert(IsRecordTy());
  return inner_struct_.lock()->GetField(name);
}

std::weak_ptr<const Struct> SizedType::GetStruct() const
{
  assert(IsRecordTy() || IsTupleTy());
  return inner_struct_;
}

} // namespace bpftrace

namespace std {
size_t hash<bpftrace::SizedType>::operator()(
    const bpftrace::SizedType &type) const
{
  auto hash = std::hash<unsigned>()(static_cast<unsigned>(type.type));
  bpftrace::hash_combine(hash, type.GetSize());

  switch (type.type)
  {
    case bpftrace::Type::integer:
      bpftrace::hash_combine(hash, type.IsSigned());
      break;
    case bpftrace::Type::pointer:
      bpftrace::hash_combine(hash, *type.GetPointeeTy());
      break;
    case bpftrace::Type::record:
      bpftrace::hash_combine(hash, type.GetName());
      break;
    case bpftrace::Type::kstack:
    case bpftrace::Type::ustack:
      bpftrace::hash_combine(hash, type.stack_type);
      break;
    case bpftrace::Type::array:
      bpftrace::hash_combine(hash, *type.GetElementTy());
      bpftrace::hash_combine(hash, type.GetNumElements());
      break;
    case bpftrace::Type::tuple:
      bpftrace::hash_combine(hash, *type.GetStruct().lock());
      break;
    // No default case (explicitly skip all remaining types instead) to get
    // a compiler warning when we add a new type
    case bpftrace::Type::none:
    case bpftrace::Type::hist:
    case bpftrace::Type::lhist:
    case bpftrace::Type::count:
    case bpftrace::Type::sum:
    case bpftrace::Type::min:
    case bpftrace::Type::max:
    case bpftrace::Type::avg:
    case bpftrace::Type::stats:
    case bpftrace::Type::string:
    case bpftrace::Type::ksym:
    case bpftrace::Type::usym:
    case bpftrace::Type::probe:
    case bpftrace::Type::username:
    case bpftrace::Type::inet:
    case bpftrace::Type::stack_mode:
    case bpftrace::Type::buffer:
    case bpftrace::Type::timestamp:
    case bpftrace::Type::mac_address:
      break;
  }

  return hash;
}
} // namespace std
