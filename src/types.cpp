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
    case Type::string:
      if (type.GetSize() == 0) {
        return typestr(type.GetTy());
      }
      return typestr(type.GetTy()) + "[" + std::to_string(type.GetSize()) + "]";
    case Type::inet:
    case Type::buffer:
      return typestr(type.GetTy()) + "[" + std::to_string(type.GetSize()) + "]";
    case Type::pointer:
      return typestr(type.GetPointeeTy()) + " *";
    case Type::array:
      return typestr(type.GetElementTy()) + "[" +
             std::to_string(type.GetNumElements()) + "]";
    case Type::c_struct: {
      if (!type.IsAnonTy())
        return type.GetName();

      // For anonymous structs/unions, return a string of the
      // format "struct { field1type,... }"
      const std::string &type_name = type.GetName();
      std::string res = type_name.substr(0, type_name.find(" "));
      size_t n = type.GetFieldCount();

      res += " {";
      for (size_t i = 0; i < n; ++i) {
        res += typestr(type.GetField(i).type);
        if (i != n - 1)
          res += ",";
      }
      res += "}";
      return res;
    }
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
    case Type::record: {
      std::string res = "record";
      size_t n = type.GetFieldCount();

      res += " { ";
      for (size_t i = 0; i < n; ++i) {
        res += "." + type.GetField(i).name;
        res += " = ";
        res += typestr(type.GetField(i).type);
        if (i != n - 1)
          res += ", ";
      }
      res += " }";
      return res;
    }
    case Type::kstack_t:
    case Type::ustack_t:
      return type.stack_type.name();
    case Type::max_t:
    case Type::min_t:
    case Type::sum_t:
    case Type::avg_t:
    case Type::stats_t:
      return (type.is_signed_ ? "" : "u") + typestr(type.GetTy());
    case Type::count_t:
    case Type::mac_address:
    case Type::timestamp:
    case Type::ksym_t:
    case Type::usym_t:
    case Type::username:
    case Type::timestamp_mode:
    case Type::cgroup_path_t:
    case Type::hist_t:
    case Type::lhist_t:
    case Type::tseries_t:
    case Type::none:
    case Type::voidtype:
    case Type::boolean:
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

bool SizedType::IsCompatible(const SizedType &t) const
{
  if (t.GetTy() != type_)
    return false;

  if (IsCStructTy())
    return t.GetName() == GetName();

  if (IsPtrTy())
    return GetPointeeTy().IsCompatible(t.GetPointeeTy());

  if (IsIntegerTy()) {
    if (IsSigned() == t.IsSigned()) {
      return true;
    }
    // If the signs don't match then then unsigned side
    // can't be promoted anymore if it's already the largest int
    if (!t.IsSigned()) {
      return t.GetSize() != 8;
    } else { // t is signed
      return GetSize() != 8;
    }
  }

  if (IsTupleTy()) {
    if (GetFieldCount() != t.GetFieldCount())
      return false;

    for (ssize_t i = 0; i < GetFieldCount(); i++) {
      if (!GetField(i).type.IsCompatible(t.GetField(i).type))
        return false;
    }
  }

  if (IsStack() && stack_type != t.stack_type) {
    return false;
  }

  if (IsRecordTy() && t.IsRecordTy()) {
    if (GetFieldCount() != t.GetFieldCount())
      return false;

    for (ssize_t i = 0; i < GetFieldCount(); i++) {
      const auto &field_left = GetField(i);
      if (!t.HasField(field_left.name)) {
        return false;
      }

      const auto &field_right = t.GetField(field_left.name);

      if (!field_left.type.IsCompatible(field_right.type))
        return false;
    }
  }

  return true;
}

bool SizedType::IsEqual(const SizedType &t) const
{
  return (*this <=> t) == 0;
}

bool SizedType::operator==(const SizedType &t) const
{
  return IsEqual(t);
}

std::strong_ordering SizedType::operator<=>(const SizedType &t) const
{
  if (auto cmp = type_ <=> t.type_; cmp != 0)
    return cmp;

  if (IsCStructTy()) {
    if (auto cmp = GetName() <=> t.GetName(); cmp != 0)
      return cmp;
    return GetSize() <=> t.GetSize();
  }

  if (IsPtrTy()) {
    return GetPointeeTy() <=> t.GetPointeeTy();
  }

  if (IsArrayTy()) {
    if (auto cmp = GetNumElements() <=> t.GetNumElements(); cmp != 0)
      return cmp;
    return GetElementTy() <=> t.GetElementTy();
  }

  if (IsTupleTy()) {
    if (auto cmp = GetFieldCount() <=> t.GetFieldCount(); cmp != 0)
      return cmp;
    for (ssize_t i = 0; i < GetFieldCount(); i++) {
      if (auto cmp = GetField(i).type <=> t.GetField(i).type; cmp != 0)
        return cmp;
    }
    return std::strong_ordering::equal;
  }

  if (IsRecordTy()) {
    if (auto cmp = GetFieldCount() <=> t.GetFieldCount(); cmp != 0)
      return cmp;

    for (ssize_t i = 0; i < GetFieldCount(); i++) {
      const auto &field_left = GetField(i);
      const auto &field_right = t.GetField(i);
      if (auto cmp = field_left.name <=> field_right.name; cmp != 0)
        return cmp;

      if (auto cmp = field_left.type <=> field_right.type; cmp != 0)
        return cmp;
    }

    return std::strong_ordering::equal;
  }

  if (auto cmp = GetSize() <=> t.GetSize(); cmp != 0)
    return cmp;

  return is_signed_ <=> t.is_signed_;
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
  return IsArrayTy() || IsByteArray() || IsTupleTy() || IsCStructTy() ||
         IsStack() || IsRecordTy();
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
    case Type::c_struct:   return "c_struct";   break;
    case Type::hist_t:     return "hist_t";     break;
    case Type::lhist_t:    return "lhist_t";    break;
    case Type::tseries_t:    return "tseries_t";    break;
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
    case Type::array:    return "array";    break;
    case Type::buffer:   return "buffer";   break;
    case Type::tuple:    return "tuple";    break;
    case Type::record:    return "record";    break;
    case Type::timestamp:return "timestamp";break;
    case Type::mac_address: return "mac_address"; break;
    case Type::cgroup_path_t: return "cgroup_path_t"; break;
    case Type::timestamp_mode: return "timestamp_mode"; break;
    case Type::boolean:     return "bool";     break;
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
  return { Type::boolean, 1 };
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

SizedType CreateCStruct(const std::string &name)
{
  assert(!name.empty());
  auto ty = SizedType(Type::c_struct, 0);
  ty.name_ = name;
  return ty;
}

SizedType CreateCStruct(std::shared_ptr<Struct> &&record)
{
  // A local anonymous record.
  assert(record);
  auto ty = SizedType(Type::c_struct, record->size);
  ty.inner_struct_ = std::move(record);
  return ty;
}

SizedType CreateCStruct(const std::string &name, std::weak_ptr<Struct> record)
{
  // A named type, stored in the `StructManager`.
  assert(!name.empty() && !record.expired());
  auto ty = SizedType(Type::c_struct, record.lock()->size);
  ty.name_ = name;
  ty.inner_struct_ = std::move(record);
  return ty;
}

SizedType CreateStack(bool kernel, StackType stack)
{
  // These sizes are based on the stack struct (see
  // IRBuilderBPF::GetStackStructType)
  auto base_size = (stack.limit * stack.elem_size()) + 8;
  auto st = SizedType(kernel ? Type::kstack_t : Type::ustack_t,
                      kernel ? base_size : (base_size + 8));
  st.stack_type = stack;
  st.stack_type.kernel = kernel;
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

SizedType CreateCount()
{
  return { Type::count_t, 8, false };
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

SizedType CreateTSeries()
{
  return { Type::tseries_t, 8 };
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

SizedType CreateRecord(std::shared_ptr<Struct> &&record)
{
  auto s = SizedType(Type::record, record->size);
  s.inner_struct_ = std::move(record);
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
  assert(IsTupleTy() || IsCStructTy() || IsRecordTy());
  return inner_struct()->fields;
}

Field &SizedType::GetField(ssize_t n) const
{
  assert(IsTupleTy() || IsCStructTy() || IsRecordTy());
  assert(n >= 0 && n < GetFieldCount());
  return inner_struct()->fields[n];
}

size_t SizedType::GetFieldIdx(const std::string &name) const
{
  assert(IsRecordTy());
  return inner_struct()->GetFieldIdx(name);
}

ssize_t SizedType::GetFieldCount() const
{
  assert(IsTupleTy() || IsCStructTy() || IsRecordTy());
  return inner_struct()->fields.size();
}

void SizedType::DumpStructure(std::ostream &os)
{
  assert(IsTupleTy() || IsRecordTy());
  if (IsTupleTy())
    os << "tuple";
  else
    os << "record";
  inner_struct()->Dump(os);
}

ssize_t SizedType::GetInTupleAlignment() const
{
  if (IsByteArray())
    return 1;

  if (IsTupleTy() || IsCStructTy() || IsRecordTy())
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
  assert(IsCStructTy() || IsRecordTy());
  return inner_struct()->HasField(name);
}

const Field &SizedType::GetField(const std::string &name) const
{
  assert(IsCStructTy() || IsRecordTy());
  return inner_struct()->GetField(name);
}

std::shared_ptr<Struct> SizedType::inner_struct() const
{
  assert(IsCStructTy() || IsTupleTy() || IsRecordTy());
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
  assert(IsCStructTy() || IsTupleTy() || IsRecordTy());
  return inner_struct();
}

bool SizedType::FitsInto(const SizedType &t) const
{
  if (!IsCompatible(t))
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

  if (IsRecordTy()) {
    if (GetFieldCount() != t.GetFieldCount())
      return false;

    for (ssize_t i = 0; i < GetFieldCount(); i++) {
      const auto &field = GetField(i);
      if (!field.type.FitsInto(t.GetField(field.name).type))
        return false;
    }
    return true;
  }
  return IsEqual(t);
}

bool SizedType::NeedsPercpuMap() const
{
  return IsHistTy() || IsLhistTy() || IsCountTy() || IsSumTy() || IsMinTy() ||
         IsMaxTy() || IsAvgTy() || IsStatsTy() || IsTSeriesTy();
}

std::ostream &operator<<(std::ostream &os, TSeriesAggFunc agg)
{
  switch (agg) {
    case TSeriesAggFunc::none:
      os << "none";
      break;
    case TSeriesAggFunc::avg:
      os << "avg";
      break;
    case TSeriesAggFunc::max:
      os << "max";
      break;
    case TSeriesAggFunc::min:
      os << "min";
      break;
    case TSeriesAggFunc::sum:
      os << "sum";
      break;
  }

  return os;
}

} // namespace bpftrace
