#include <cassert>
#include <iostream>
#include <sstream>

#include "ast/async_event_types.h"
#include "struct.h"
#include "types.h"
#include "util/exceptions.h"

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
    return *t.inner_struct() == *inner_struct();

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
  return { Type::string, size };
}

SizedType CreateNone()
{
  return { Type::none, 0 };
}

SizedType CreateVoid()
{
  return { Type::voidtype, 0 };
}

SizedType CreateStackMode()
{
  return { Type::stack_mode, 0 };
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

SizedType CreateRecord(const std::string &name)
{
  assert(!name.empty());
  auto ty = SizedType(Type::record, 0);
  ty.name_ = name;
  return ty;
}

SizedType CreateRecord(std::shared_ptr<Struct> &&record)
{
  // A local anonymous record.
  assert(record);
  auto ty = SizedType(Type::record, record->size);
  ty.inner_struct_ = std::move(record);
  return ty;
}

SizedType CreateRecord(const std::string &name, std::weak_ptr<Struct> record)
{
  // A named type, stored in the `StructManager`.
  assert(!name.empty() && !record.expired());
  auto ty = SizedType(Type::record, record.lock()->size);
  ty.name_ = name;
  ty.inner_struct_ = std::move(record);
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
  return { Type::min_t, 8, is_signed };
}

SizedType CreateMax(bool is_signed)
{
  return { Type::max_t, 8, is_signed };
}

SizedType CreateSum(bool is_signed)
{
  return { Type::sum_t, 8, is_signed };
}

SizedType CreateCount(bool is_signed)
{
  return { Type::count_t, 8, is_signed };
}

SizedType CreateAvg(bool is_signed)
{
  return { Type::avg_t, 8, is_signed };
}

SizedType CreateStats(bool is_signed)
{
  return { Type::stats_t, 8, is_signed };
}

SizedType CreateUsername()
{
  return { Type::username, 8 };
}

SizedType CreateInet(size_t size)
{
  auto st = SizedType(Type::inet, size);
  st.is_internal = true;
  return st;
}

SizedType CreateLhist()
{
  return { Type::lhist_t, 8 };
}

SizedType CreateHist()
{
  return { Type::hist_t, 8 };
}

SizedType CreateUSym()
{
  return { Type::usym_t, 16 };
}

SizedType CreateKSym()
{
  return { Type::ksym_t, 8 };
}

SizedType CreateBuffer(size_t size)
{
  auto metadata_headroom_bytes = sizeof(AsyncEvent::Buf);
  return { Type::buffer, size + metadata_headroom_bytes };
}

SizedType CreateTimestamp()
{
  return { Type::timestamp, 16 };
}

SizedType CreateTuple(std::shared_ptr<Struct> &&tuple)
{
  auto s = SizedType(Type::tuple, tuple->size);
  s.inner_struct_ = std::move(tuple);
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
  return { Type::cgroup_path_t, 16 };
}

SizedType CreateStrerror()
{
  return { Type::strerror_t, 8 };
}

SizedType CreateTimestampMode()
{
  return { Type::timestamp_mode, 0 };
}

bool SizedType::IsSigned() const
{
  return is_signed_;
}

std::vector<Field> &SizedType::GetFields() const
{
  assert(IsTupleTy() || IsRecordTy());
  return inner_struct()->fields;
}

Field &SizedType::GetField(ssize_t n) const
{
  assert(IsTupleTy() || IsRecordTy());
  if (n >= GetFieldCount())
    throw util::FatalUserException("Getfield(): out of bounds");
  return inner_struct()->fields[n];
}

ssize_t SizedType::GetFieldCount() const
{
  assert(IsTupleTy() || IsRecordTy());
  return inner_struct()->fields.size();
}

void SizedType::DumpStructure(std::ostream &os)
{
  assert(IsTupleTy());
  if (IsTupleTy())
    os << "tuple";
  else
    os << "struct";
  inner_struct()->Dump(os);
}

ssize_t SizedType::GetInTupleAlignment() const
{
  if (IsByteArray())
    return 1;

  if (IsTupleTy() || IsRecordTy())
    return inner_struct()->align;

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
  return inner_struct()->HasField(name);
}

const Field &SizedType::GetField(const std::string &name) const
{
  assert(IsRecordTy());
  return inner_struct()->GetField(name);
}

std::shared_ptr<Struct> SizedType::inner_struct() const
{
  assert(IsRecordTy() || IsTupleTy());
  return std::visit(
      [](const auto &v) {
        if constexpr (std::is_same_v<std::decay_t<decltype(v)>,
                                     std::weak_ptr<Struct>>) {
          return v.lock();
        } else {
          return v;
        }
      },
      inner_struct_);
}

std::shared_ptr<const Struct> SizedType::GetStruct() const
{
  assert(IsRecordTy() || IsTupleTy());
  return inner_struct();
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
