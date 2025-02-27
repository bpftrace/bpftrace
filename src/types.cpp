#include <algorithm>
#include <cassert>
#include <iostream>
#include <sstream>

#include "ast/async_event_types.h"
#include "bpftrace.h"
#include "log.h"
#include "struct.h"
#include "types.h"
#include "utils.h"

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
  os << typestr(type);
  return os;
}

std::string typestr(const SizedType &type)
{
  switch (type.GetTy()) {
    case Type::integer:
      if (type.IsEnumTy()) {
        return "enum " + type.GetName();
      }
      return (type.is_signed_ ? "int" : "uint") +
             std::to_string(8 * type.GetSize());
    case Type::inet:
    case Type::string:
    case Type::buffer:
      return typestr(type.GetTy()) + "[" + std::to_string(type.GetSize()) + "]";
    case Type::pointer: {
      std::string prefix;
      if (type.IsCtxAccess())
        prefix = "(ctx) ";
      return prefix + typestr(*type.GetPointeeTy()) + " *";
    }
    case Type::array:
      return typestr(*type.GetElementTy()) + "[" +
             std::to_string(type.GetNumElements()) + "]";
    case Type::record:
      return type.GetName();
    case Type::reference:
      return typestr(*type.GetDereferencedTy()) + " &";
    case Type::tuple: {
      std::string res = "(";
      size_t n = type.GetFieldCount();
      for (size_t i = 0; i < n; ++i) {
        res += typestr(type.GetField(i).type);
        if (i != n - 1)
          res += ",";
      }
      res += ")";
      return res;
    }
    case Type::max_t:
    case Type::min_t:
    case Type::sum_t:
    case Type::avg_t:
    case Type::count_t:
    case Type::stats_t:
      return (type.is_signed_ ? "" : "u") + typestr(type.GetTy());
    case Type::mac_address:
    case Type::kstack_t:
    case Type::ustack_t:
    case Type::timestamp:
    case Type::ksym_t:
    case Type::usym_t:
    case Type::username:
    case Type::stack_mode:
    case Type::timestamp_mode:
    case Type::cgroup_path_t:
    case Type::strerror_t:
    case Type::hist_t:
    case Type::lhist_t:
    case Type::none:
    case Type::voidtype:
      return typestr(type.GetTy());
  }

  __builtin_unreachable();
}

std::string to_string(Type ty)
{
  std::ostringstream ss;
  ss << ty;
  return ss.str();
}

bool SizedType::IsSameType(const SizedType &t) const
{
  if (t.GetTy() != type_)
    return false;

  if (IsRecordTy())
    return t.GetName() == GetName();

  if (IsPtrTy() && t.IsPtrTy())
    return GetPointeeTy()->IsSameType(*t.GetPointeeTy());

  if (IsTupleTy() && t.IsTupleTy()) {
    if (GetFieldCount() != t.GetFieldCount())
      return false;

    for (ssize_t i = 0; i < GetFieldCount(); i++) {
      if (!GetField(i).type.IsSameType(t.GetField(i).type))
        return false;
    }
  }

  return type_ == t.GetTy();
}

bool SizedType::IsEqual(const SizedType &t) const
{
  if (t.GetTy() != type_)
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

  return type_ == t.GetTy() && GetSize() == t.GetSize() &&
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
  return type_ == Type::string || type_ == Type::usym_t ||
         type_ == Type::inet || type_ == Type::buffer ||
         type_ == Type::timestamp || type_ == Type::mac_address ||
         type_ == Type::cgroup_path_t;
}

bool SizedType::IsAggregate() const
{
  return IsArrayTy() || IsByteArray() || IsTupleTy() || IsRecordTy() ||
         IsStack();
}

bool SizedType::IsStack() const
{
  return type_ == Type::ustack_t || type_ == Type::kstack_t;
}

std::string addrspacestr(AddrSpace as)
{
  switch (as) {
    case AddrSpace::kernel:
      return "kernel";
      break;
    case AddrSpace::user:
      return "user";
      break;
    case AddrSpace::bpf:
      return "bpf";
      break;
    case AddrSpace::none:
      return "none";
      break;
  }

  return {}; // unreached
}

std::string typestr(Type t)
{
  switch (t) {
      // clang-format off
    case Type::none:     return "none";     break;
    case Type::voidtype: return "void";     break;
    case Type::integer:  return "int";  break;
    case Type::pointer:  return "pointer";  break;
    case Type::reference:return "reference";break;
    case Type::record:   return "record";   break;
    case Type::hist_t:     return "hist_t";     break;
    case Type::lhist_t:    return "lhist_t";    break;
    case Type::count_t:    return "count_t";    break;
    case Type::sum_t:      return "sum_t";      break;
    case Type::min_t:      return "min_t";      break;
    case Type::max_t:      return "max_t";      break;
    case Type::avg_t:      return "avg_t";      break;
    case Type::stats_t:    return "stats_t";    break;
    case Type::kstack_t:   return "kstack";   break;
    case Type::ustack_t:   return "ustack";   break;
    case Type::string:   return "string";   break;
    case Type::ksym_t:     return "ksym_t";     break;
    case Type::usym_t:     return "usym_t";     break;
    case Type::username: return "username"; break;
    case Type::inet:     return "inet";     break;
    case Type::stack_mode:return "stack_mode";break;
    case Type::array:    return "array";    break;
    case Type::buffer:   return "buffer";   break;
    case Type::tuple:    return "tuple";    break;
    case Type::timestamp:return "timestamp";break;
    case Type::mac_address: return "mac_address"; break;
    case Type::cgroup_path_t: return "cgroup_path_t"; break;
    case Type::strerror_t: return "strerror_t"; break;
    case Type::timestamp_mode: return "timestamp_mode"; break;
      // clang-format on
  }

  return {}; // unreached
}

ProbeType probetype(const std::string &probeName)
{
  ProbeType retType = ProbeType::invalid;

  auto v = std::find_if(PROBE_LIST.begin(),
                        PROBE_LIST.end(),
                        [&probeName](const ProbeItem &p) {
                          return (p.name == probeName ||
                                  p.aliases.find(probeName) != p.aliases.end());
                        });

  if (v != PROBE_LIST.end())
    retType = v->type;

  return retType;
}

std::string expand_probe_name(const std::string &orig_name)
{
  std::string expanded_name = orig_name;

  auto v = std::find_if(PROBE_LIST.begin(),
                        PROBE_LIST.end(),
                        [&orig_name](const ProbeItem &p) {
                          return (p.name == orig_name ||
                                  p.aliases.find(orig_name) != p.aliases.end());
                        });

  if (v != PROBE_LIST.end())
    expanded_name = v->name;

  return expanded_name;
}

std::string probetypeName(ProbeType t)
{
  // clang-format off
  switch (t)
  {
    case ProbeType::invalid:     return "invalid";     break;
    case ProbeType::special:     return "special";     break;
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
    case ProbeType::asyncwatchpoint: return "asyncwatchpoint"; break;
    case ProbeType::fentry:      return "fentry";       break;
    case ProbeType::fexit:       return "fexit";    break;
    case ProbeType::iter:        return "iter";        break;
    case ProbeType::rawtracepoint: return "rawtracepoint";  break;
  }
  // clang-format on

  return {}; // unreached
}

uint64_t asyncactionint(AsyncAction a)
{
  return static_cast<uint64_t>(a);
}

// Type wrappers
SizedType CreateInteger(size_t bits, bool is_signed)
{
  auto t = SizedType(Type::integer, 0, is_signed);
  t.SetIntBitWidth(bits);
  return t;
}

SizedType CreateBool()
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

SizedType CreateEnum(size_t bits, const std::string &name)
{
  auto ty = CreateUInt(bits);
  ty.name_ = name;
  return ty;
}

SizedType CreateString(size_t size)
{
  return SizedType(Type::string, size);
}

SizedType CreateNone()
{
  return SizedType(Type::none, 0);
}

SizedType CreateVoid()
{
  return SizedType(Type::voidtype, 0);
}

SizedType CreateStackMode()
{
  return SizedType(Type::stack_mode, 0);
}

SizedType CreateArray(size_t num_elements, const SizedType &element_type)
{
  size_t size = num_elements * element_type.GetSize();
  auto ty = SizedType(Type::array, size);
  ty.element_type_ = std::make_shared<SizedType>(element_type);
  ty.num_elements_ = num_elements;
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

SizedType CreateReference(const SizedType &referred_type, AddrSpace as)
{
  // Reference itself is always an uint64
  auto ty = SizedType(Type::reference, 8);
  ty.element_type_ = std::make_shared<SizedType>(referred_type);
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
  // These sizes are based on the stack key (see
  // IRBuilderBPF::GetStackStructType) but include struct padding
  auto st = SizedType(kernel ? Type::kstack_t : Type::ustack_t,
                      kernel ? 16 : 24);
  st.stack_type = stack;
  return st;
}

SizedType CreateMin(bool is_signed)
{
  return SizedType(Type::min_t, 8, is_signed);
}

SizedType CreateMax(bool is_signed)
{
  return SizedType(Type::max_t, 8, is_signed);
}

SizedType CreateSum(bool is_signed)
{
  return SizedType(Type::sum_t, 8, is_signed);
}

SizedType CreateCount(bool is_signed)
{
  return SizedType(Type::count_t, 8, is_signed);
}

SizedType CreateAvg(bool is_signed)
{
  return SizedType(Type::avg_t, 8, is_signed);
}

SizedType CreateStats(bool is_signed)
{
  return SizedType(Type::stats_t, 8, is_signed);
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
  return SizedType(Type::lhist_t, 8);
}

SizedType CreateHist()
{
  return SizedType(Type::hist_t, 8);
}

SizedType CreateUSym()
{
  return SizedType(Type::usym_t, 16);
}

SizedType CreateKSym()
{
  return SizedType(Type::ksym_t, 8);
}

SizedType CreateBuffer(size_t size)
{
  auto metadata_headroom_bytes = sizeof(AsyncEvent::Buf);
  return SizedType(Type::buffer, size + metadata_headroom_bytes);
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

SizedType CreateCgroupPath()
{
  return SizedType(Type::cgroup_path_t, 16);
}

SizedType CreateStrerror()
{
  return SizedType(Type::strerror_t, 8);
}

SizedType CreateTimestampMode()
{
  return SizedType(Type::timestamp_mode, 0);
}

bool SizedType::IsSigned() const
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
    throw FatalUserException("Getfield(): out of bounds");
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

ssize_t SizedType::GetInTupleAlignment() const
{
  if (IsByteArray())
    return 1;

  if (IsTupleTy() || IsRecordTy())
    return inner_struct_.lock()->align;

  if (GetSize() <= 2)
    return GetSize();
  else if (IsArrayTy())
    return element_type_->GetInTupleAlignment();
  else if (GetSize() <= 4)
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

bool SizedType::IsSameSizeRecursive(const SizedType &t) const
{
  if (GetSize() != t.GetSize()) {
    return false;
  }

  if (IsTupleTy() && t.IsTupleTy()) {
    if (GetFieldCount() != t.GetFieldCount()) {
      return false;
    }

    for (ssize_t i = 0; i < GetFieldCount(); i++) {
      if (!GetField(i).type.IsSameSizeRecursive(t.GetField(i).type))
        return false;
    }
  }

  return true;
}

bool SizedType::FitsInto(const SizedType &t) const
{
  if (!IsSameType(t))
    return false;

  if (IsStringTy() && t.IsStringTy())
    return GetSize() <= t.GetSize();

  if (IsIntegerTy()) {
    if (IsSigned() == t.IsSigned())
      return GetSize() <= t.GetSize();

    // Unsigned into signed requires the destination to be bigger than the
    // source, e.g. uint32 -> int64.  uint32 does not fit into int32.
    if (!IsSigned())
      return GetSize() < t.GetSize();

    return false; // signed never fits into unsigned
  }

  if (IsTupleTy()) {
    if (GetFieldCount() != t.GetFieldCount())
      return false;

    for (ssize_t i = 0; i < GetFieldCount(); i++) {
      if (!GetField(i).type.FitsInto(t.GetField(i).type))
        return false;
    }
    return true;
  }
  return IsEqual(t);
}

bool SizedType::NeedsPercpuMap() const
{
  return IsHistTy() || IsLhistTy() || IsCountTy() || IsSumTy() || IsMinTy() ||
         IsMaxTy() || IsAvgTy() || IsStatsTy();
}
} // namespace bpftrace

namespace std {
size_t hash<bpftrace::SizedType>::operator()(
    const bpftrace::SizedType &type) const
{
  auto hash = std::hash<unsigned>()(static_cast<unsigned>(type.GetTy()));
  bpftrace::hash_combine(hash, type.GetSize());

  switch (type.GetTy()) {
    case bpftrace::Type::integer:
      bpftrace::hash_combine(hash, type.IsSigned());
      break;
    case bpftrace::Type::pointer:
      bpftrace::hash_combine(hash, *type.GetPointeeTy());
      break;
    case bpftrace::Type::reference:
      bpftrace::hash_combine(hash, *type.GetDereferencedTy());
      break;
    case bpftrace::Type::record:
      bpftrace::hash_combine(hash, type.GetName());
      break;
    case bpftrace::Type::kstack_t:
    case bpftrace::Type::ustack_t:
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
    case bpftrace::Type::voidtype:
    case bpftrace::Type::hist_t:
    case bpftrace::Type::lhist_t:
    case bpftrace::Type::count_t:
    case bpftrace::Type::sum_t:
    case bpftrace::Type::min_t:
    case bpftrace::Type::max_t:
    case bpftrace::Type::avg_t:
    case bpftrace::Type::stats_t:
    case bpftrace::Type::string:
    case bpftrace::Type::ksym_t:
    case bpftrace::Type::usym_t:
    case bpftrace::Type::username:
    case bpftrace::Type::inet:
    case bpftrace::Type::stack_mode:
    case bpftrace::Type::buffer:
    case bpftrace::Type::timestamp:
    case bpftrace::Type::mac_address:
    case bpftrace::Type::cgroup_path_t:
    case bpftrace::Type::strerror_t:
    case bpftrace::Type::timestamp_mode:
      break;
  }

  return hash;
}
} // namespace std
