#pragma once

#include <algorithm>
#include <cassert>
#include <cereal/access.hpp>
#include <cereal/types/variant.hpp>
#include <compare>
#include <map>
#include <memory>
#include <ostream>
#include <string>
#include <sys/types.h>
#include <unistd.h>
#include <unordered_set>
#include <variant>
#include <vector>

#include "config_parser.h"
#include "util/result.h"

namespace bpftrace {

enum class Type : uint8_t {
  // clang-format off
  none,
  voidtype,
  integer, // int is a protected keyword
  boolean,
  pointer,
  record, // struct/union, as struct is a protected keyword
  hist_t,
  lhist_t,
  tseries_t,
  count_t,
  sum_t,
  min_t,
  max_t,
  avg_t,
  stats_t,
  kstack_t,
  ustack_t,
  string,
  ksym_t,
  usym_t,
  username,
  inet,
  stack_mode,
  array,
  buffer,
  tuple,
  timestamp,
  mac_address,
  cgroup_path_t,
  timestamp_mode,
  // clang-format on
};

enum class AddrSpace : uint8_t {
  none,
  kernel,
  user,
};

std::ostream &operator<<(std::ostream &os, Type type);
std::ostream &operator<<(std::ostream &os, AddrSpace as);
std::string to_string(Type ty);

enum class UserSymbolCacheType {
  per_pid,
  per_program,
  none,
};

enum class StackMode : uint8_t {
  bpftrace,
  perf,
  raw,
};

const std::map<StackMode, std::string> STACK_MODE_NAME_MAP = {
  { StackMode::bpftrace, "bpftrace" },
  { StackMode::perf, "perf" },
  { StackMode::raw, "raw" },
};

template <>
struct ConfigParser<StackMode> {
  Result<OK> parse(const std::string &key,
                   StackMode *target,
                   const std::string &s)
  {
    // Scan to through and match against a valid name.
    for (const auto &[mode, name] : STACK_MODE_NAME_MAP) {
      if (s == name) {
        *target = mode;
        return OK();
      }
    }
    return make_error<ParseError>(key,
                                  "Invalid value for stack_mode: valid "
                                  "values are bpftrace, raw and perf.");
  }
  Result<OK> parse(const std::string &key,
                   [[maybe_unused]] StackMode *target,
                   [[maybe_unused]] uint64_t v)
  {
    return make_error<ParseError>(key,
                                  "Invalid value for stack_mode: valid "
                                  "values are bpftrace, raw and perf.");
  }
};

struct StackType {
  // N.B. the limit of 127 defines the default stack size.
  uint16_t limit = 127;
  StackMode mode = StackMode::bpftrace;

  bool operator==(const StackType &obj) const
  {
    return limit == obj.limit && mode == obj.mode;
  }

  std::string name() const
  {
    return "stack_" + STACK_MODE_NAME_MAP.at(mode) + "_" +
           std::to_string(limit);
  }

  static const std::string &scratch_name()
  {
    static const std::string scratch_name = "stack_scratch";
    return scratch_name;
  }

private:
  friend class cereal::access;
  template <typename Archive>
  void serialize(Archive &archive)
  {
    archive(limit, mode);
  }
};

enum class TimestampMode : uint8_t {
  monotonic,
  boot,
  tai,
  sw_tai,
};

struct Struct;
struct Field;

class SizedType {
public:
  SizedType() : type_(Type::none)
  {
  }
  SizedType(Type type, size_t size_, bool is_signed)
      : type_(type), size_bits_(size_ * 8), is_signed_(is_signed)
  {
  }
  SizedType(Type type, size_t size_) : type_(type), size_bits_(size_ * 8)
  {
  }

  StackType stack_type;
  int funcarg_idx = -1;
  bool is_internal = false;
  bool is_funcarg = false;
  TimestampMode ts_mode = TimestampMode::boot;

private:
  Type type_;
  size_t size_bits_ = 0;                    // size in bits
  std::shared_ptr<SizedType> element_type_; // for "container" and pointer
                                            // (like) types
  std::string name_; // name of this type, for named types like struct and enum
  std::variant<std::shared_ptr<Struct>, std::weak_ptr<Struct>>
      inner_struct_; // inner struct for records and tuples: if a shared_ptr, it
                     // is an anonymous type, if it is a weak_ptr, then it is
                     // owned by the `StructManager`.
  AddrSpace as_ = AddrSpace::none;
  bool is_signed_ = false;
  bool is_anon_ = false;
  bool ctx_ = false;                              // Is bpf program context
  std::unordered_set<std::string> btf_type_tags_; // Only populated for
                                                  // Type::pointer
  size_t num_elements_ = 0; // Only populated for array types

  std::shared_ptr<Struct> inner_struct() const;

  friend class cereal::access;
  template <typename Archive>
  void serialize(Archive &archive)
  {
    archive(type_,
            stack_type,
            is_internal,
            is_funcarg,
            is_anon_,
            funcarg_idx,
            is_signed_,
            element_type_,
            name_,
            ctx_,
            as_,
            size_bits_,
            inner_struct_);
  }

public:
  // Tuple/struct accessors
  std::vector<Field> &GetFields() const;
  bool HasField(const std::string &name) const;
  const Field &GetField(const std::string &name) const;
  Field &GetField(ssize_t n) const;
  ssize_t GetFieldCount() const;
  std::shared_ptr<const Struct> GetStruct() const;

  // Required alignment for this type when used inside a tuple
  ssize_t GetInTupleAlignment() const;

  // Dump the underlying structure for debug purposes
  void DumpStructure(std::ostream &os);

  AddrSpace GetAS() const
  {
    return as_;
  }

  void SetAS(AddrSpace as)
  {
    as_ = as;
  }

  void SetBtfTypeTags(std::unordered_set<std::string> &&tags)
  {
    assert(IsPtrTy());
    btf_type_tags_ = std::move(tags);
  }

  const std::unordered_set<std::string> &GetBtfTypeTags() const
  {
    assert(IsPtrTy());
    return btf_type_tags_;
  }

  bool IsCtxAccess() const
  {
    return ctx_;
  };

  void MarkCtxAccess()
  {
    ctx_ = true;
  };

  bool IsByteArray() const;
  bool IsAggregate() const;
  bool IsStack() const;

  bool IsEqual(const SizedType &t) const;
  bool operator==(const SizedType &t) const;
  std::strong_ordering operator<=>(const SizedType &t) const;
  bool IsSameType(const SizedType &t) const;
  bool FitsInto(const SizedType &t) const;

  bool IsPrintableTy() const
  {
    return type_ != Type::none && type_ != Type::stack_mode &&
           type_ != Type::timestamp_mode &&
           (!IsCtxAccess() || is_funcarg); // args builtin is printable
  }

  void SetSign(bool is_signed)
  {
    is_signed_ = is_signed;
  }

  bool IsSigned() const;

  size_t GetSize() const
  {
    return size_bits_ / 8;
  }

  void SetSize(size_t byte_size)
  {
    if (IsIntTy())
      SetIntBitWidth(byte_size * 8);
    else
      size_bits_ = byte_size * 8;
  }

  void SetIntBitWidth(size_t bits)
  {
    assert(IsIntTy());
    // Truncate integers too large to fit in BPF registers (64-bits).
    bits = std::min<size_t>(bits, 64);
    // Zero sized integers are not usually valid. However, during semantic
    // analysis when we're inferring types, the first pass may not have
    // enough information to figure out the exact size of the integer. Later
    // passes infer the exact size.
    assert(bits == 0 || bits == 1 || bits == 8 || bits == 16 || bits == 32 ||
           bits == 64);
    size_bits_ = bits;
  }

  size_t GetIntBitWidth() const
  {
    assert(IsIntTy());
    return size_bits_;
  };

  size_t GetNumElements() const
  {
    assert(IsArrayTy());
    // For arrays we can't just do size_bits_ / element_type.GetSize()
    // because we might not know the size of the element type (it may be 0)
    // if it's being resolved in a later AST pass e.g. for an imported type:
    // `let $x: struct Foo[10];`
    return num_elements_;
  };

  const std::string &GetName() const
  {
    assert(IsRecordTy() || IsEnumTy());
    return name_;
  }

  bool IsAnonTy() const
  {
    assert(IsRecordTy());
    return is_anon_;
  }

  void SetAnon()
  {
    assert(IsRecordTy());
    is_anon_ = true;
  }

  Type GetTy() const
  {
    return type_;
  }

  const SizedType *GetElementTy() const
  {
    assert(IsArrayTy());
    return element_type_.get();
  }

  const SizedType *GetPointeeTy() const
  {
    assert(IsPtrTy());
    return element_type_.get();
  }

  bool IsPtrTy() const
  {
    return type_ == Type::pointer;
  };
  bool IsIntTy() const
  {
    return type_ == Type::integer;
  };
  bool IsBoolTy() const
  {
    return type_ == Type::boolean;
  }
  bool IsEnumTy() const
  {
    return IsIntTy() && !name_.empty();
  }
  bool IsNoneTy() const
  {
    return type_ == Type::none;
  };
  bool IsVoidTy() const
  {
    return type_ == Type::voidtype;
  };
  bool IsIntegerTy() const
  {
    return type_ == Type::integer;
  };
  bool IsHistTy() const
  {
    return type_ == Type::hist_t;
  };
  bool IsLhistTy() const
  {
    return type_ == Type::lhist_t;
  };
  bool IsTSeriesTy() const
  {
    return type_ == Type::tseries_t;
  };
  bool IsCountTy() const
  {
    return type_ == Type::count_t;
  };
  bool IsSumTy() const
  {
    return type_ == Type::sum_t;
  };
  bool IsMinTy() const
  {
    return type_ == Type::min_t;
  };
  bool IsMaxTy() const
  {
    return type_ == Type::max_t;
  };
  bool IsAvgTy() const
  {
    return type_ == Type::avg_t;
  };
  bool IsStatsTy() const
  {
    return type_ == Type::stats_t;
  };
  bool IsKstackTy() const
  {
    return type_ == Type::kstack_t;
  };
  bool IsUstackTy() const
  {
    return type_ == Type::ustack_t;
  };
  bool IsStringTy() const
  {
    return type_ == Type::string;
  };
  bool IsKsymTy() const
  {
    return type_ == Type::ksym_t;
  };
  bool IsUsymTy() const
  {
    return type_ == Type::usym_t;
  };
  bool IsUsernameTy() const
  {
    return type_ == Type::username;
  };
  bool IsInetTy() const
  {
    return type_ == Type::inet;
  };
  bool IsStackModeTy() const
  {
    return type_ == Type::stack_mode;
  };
  bool IsArrayTy() const
  {
    return type_ == Type::array;
  };
  bool IsRecordTy() const
  {
    return type_ == Type::record;
  };
  bool IsBufferTy() const
  {
    return type_ == Type::buffer;
  };
  bool IsTupleTy() const
  {
    return type_ == Type::tuple;
  };
  bool IsTimestampTy() const
  {
    return type_ == Type::timestamp;
  };
  bool IsMacAddressTy() const
  {
    return type_ == Type::mac_address;
  };
  bool IsCgroupPathTy() const
  {
    return type_ == Type::cgroup_path_t;
  };
  bool IsTimestampModeTy() const
  {
    return type_ == Type::timestamp_mode;
  }
  bool IsCastableMapTy() const
  {
    return type_ == Type::count_t || type_ == Type::sum_t ||
           type_ == Type::max_t || type_ == Type::min_t || type_ == Type::avg_t;
  }
  bool IsMapIterableTy() const
  {
    if (IsMultiKeyMapTy()) {
      return false;
    }
    if (NeedsPercpuMap() && !IsCastableMapTy()) {
      return false;
    }
    return true;
  }

  // These are special map value types that use multiple keys to store a single
  // logical value (from the user perspective).
  bool IsMultiKeyMapTy() const
  {
    return type_ == Type::hist_t || type_ == Type::lhist_t ||
           type_ == Type::tseries_t;
  }

  bool NeedsPercpuMap() const;

  friend std::string typestr(const SizedType &type);

  // Factories

  friend SizedType CreateEnum(size_t bits, const std::string &name);
  friend SizedType CreateArray(size_t num_elements,
                               const SizedType &element_type);

  friend SizedType CreatePointer(const SizedType &pointee_type, AddrSpace as);
  friend SizedType CreateRecord(const std::string &name);
  friend SizedType CreateRecord(std::shared_ptr<Struct> &&record);
  friend SizedType CreateRecord(const std::string &name,
                                std::weak_ptr<Struct> record);
  friend SizedType CreateInteger(size_t bits, bool is_signed);
  friend SizedType CreateTuple(std::shared_ptr<Struct> &&tuple);
};

// Type helpers
SizedType CreateNone();
SizedType CreateVoid();
SizedType CreateBool();
SizedType CreateInteger(size_t bits, bool is_signed);
SizedType CreateInt(size_t bits);
SizedType CreateUInt(size_t bits);
SizedType CreateInt8();
SizedType CreateInt16();
SizedType CreateInt32();
SizedType CreateInt64();
SizedType CreateUInt8();
SizedType CreateUInt16();
SizedType CreateUInt32();
SizedType CreateUInt64();
SizedType CreateEnum(size_t bits, const std::string &name);

// Create a string of `size` bytes, inclusive of NUL terminator.
SizedType CreateString(size_t size);
SizedType CreateArray(size_t num_elements, const SizedType &element_type);
SizedType CreatePointer(const SizedType &pointee_type,
                        AddrSpace as = AddrSpace::none);

SizedType CreateRecord(const std::string &name);
SizedType CreateRecord(std::shared_ptr<Struct> &&record);
SizedType CreateRecord(const std::string &name, std::weak_ptr<Struct> record);
SizedType CreateTuple(std::shared_ptr<Struct> &&tuple);

SizedType CreateStackMode();
SizedType CreateStack(bool kernel, StackType st = StackType());

SizedType CreateMin(bool is_signed);
SizedType CreateMax(bool is_signed);
SizedType CreateSum(bool is_signed);
SizedType CreateCount();
SizedType CreateAvg(bool is_signed);
SizedType CreateStats(bool is_signed);
SizedType CreateUsername();
SizedType CreateInet(size_t size);
SizedType CreateLhist();
SizedType CreateTSeries();
SizedType CreateHist();
SizedType CreateUSym();
SizedType CreateKSym();
SizedType CreateBuffer(size_t size);
SizedType CreateTimestamp();
SizedType CreateMacAddress();
SizedType CreateCgroupPath();
SizedType CreateTimestampMode();

std::string addrspacestr(AddrSpace as);
std::string typestr(Type t);
std::string typestr(const SizedType &type);
std::ostream &operator<<(std::ostream &os, const SizedType &type);

enum class TSeriesAggFunc { none, avg, max, min, sum };

std::ostream &operator<<(std::ostream &os, TSeriesAggFunc agg);

} // namespace bpftrace

namespace std {
template <>
struct hash<bpftrace::StackType> {
  size_t operator()(const bpftrace::StackType &obj) const
  {
    switch (obj.mode) {
      case bpftrace::StackMode::bpftrace:
        return std::hash<std::string>()("bpftrace#" + to_string(obj.limit));
      case bpftrace::StackMode::perf:
        return std::hash<std::string>()("perf#" + to_string(obj.limit));
      case bpftrace::StackMode::raw:
        return std::hash<std::string>()("raw#" + to_string(obj.limit));
    }

    return {}; // unreached
  }
};
} // namespace std
