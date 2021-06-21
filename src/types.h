#pragma once

#include <cassert>
#include <map>
#include <memory>
#include <ostream>
#include <sstream>
#include <string>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

#include <cereal/access.hpp>

namespace bpftrace {

const int MAX_STACK_SIZE = 1024;
const int DEFAULT_STACK_SIZE = 127;
const int STRING_SIZE = 64;
const int COMM_SIZE = 16;

enum class Type
{
  // clang-format off
  none,
  integer,
  pointer,
  record, // struct/union, as struct is a protected keyword
  hist,
  lhist,
  count,
  sum,
  min,
  max,
  avg,
  stats,
  kstack,
  ustack,
  string,
  ksym,
  usym,
  probe,
  username,
  inet,
  stack_mode,
  array,
  buffer,
  tuple,
  timestamp,
  mac_address
  // clang-format on
};

enum class AddrSpace
{
  none,
  kernel,
  user,
};

std::ostream &operator<<(std::ostream &os, Type type);
std::ostream &operator<<(std::ostream &os, AddrSpace as);

enum class StackMode
{
  bpftrace,
  perf,
};

struct StackType
{
  size_t limit = DEFAULT_STACK_SIZE;
  StackMode mode = StackMode::bpftrace;

  bool operator ==(const StackType &obj) const {
    return limit == obj.limit && mode == obj.mode;
  }

private:
  friend class cereal::access;
  template <typename Archive>
  void serialize(Archive &archive)
  {
    archive(limit, mode);
  }
};

class BPFtrace;
struct Struct;
struct Field;

class SizedType
{
public:
  SizedType() : type(Type::none), size_(0)
  {
  }
  SizedType(Type type, size_t size_, bool is_signed)
      : type(type), size_(size_), is_signed_(is_signed)
  {
  }
  SizedType(Type type, size_t size_) : type(type), size_(size_)
  {
  }

  Type type;
  StackType stack_type;
  bool is_internal = false;
  bool is_tparg = false;
  bool is_kfarg = false;
  int kfarg_idx = -1;

private:
  size_t size_ = -1; // in bytes
  bool is_signed_ = false;
  std::shared_ptr<SizedType> element_type_; // for "container" and pointer
                                            // (like) types
  size_t num_elements_ = -1;                // for array like types
  std::string name_; // name of this type, for named types like struct
  bool ctx_ = false; // Is bpf program context
  AddrSpace as_ = AddrSpace::none;
  ssize_t size_bits_ = -1; // size in bits for integer types

  std::weak_ptr<Struct> inner_struct_; // inner struct for records and tuples
                                       // the actual Struct object is owned by
                                       // StructManager

  friend class cereal::access;
  template <typename Archive>
  void serialize(Archive &archive)
  {
    archive(type,
            stack_type,
            is_internal,
            is_tparg,
            is_kfarg,
            kfarg_idx,
            size_,
            is_signed_,
            element_type_,
            num_elements_,
            name_,
            ctx_,
            as_,
            size_bits_,
            inner_struct_);
  }

public:
  /**
     Tuple/struct accessors
  */
  std::vector<Field> &GetFields() const;
  bool HasField(const std::string &name) const;
  const Field &GetField(const std::string &name) const;
  Field &GetField(ssize_t n) const;
  ssize_t GetFieldCount() const;
  std::weak_ptr<const Struct> GetStruct() const;

  /**
     Required alignment for this type
   */
  ssize_t GetAlignment() const;

  /**
     Dump the underlying structure for debug purposes
  */
  void DumpStructure(std::ostream &os);

  AddrSpace GetAS() const
  {
    return as_;
  }

  void SetAS(AddrSpace as)
  {
    as_ = as;
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
  bool operator!=(const SizedType &t) const;
  bool IsSameType(const SizedType &t) const;

  bool IsPrintableTy()
  {
    return type != Type::none && type != Type::pointer &&
           type != Type::stack_mode && !IsCtxAccess();
  }

  bool IsSigned(void) const;

  size_t GetSize() const
  {
    return size_;
  }

  void SetSize(size_t size)
  {
    size_ = size;
    if (IsIntTy())
    {
      assert(size == 0 || size == 1 || size == 8 || size == 16 || size == 32 ||
             size == 64);
      size_bits_ = size * 8;
    }
  }

  size_t GetIntBitWidth() const
  {
    assert(IsIntTy());
    return size_bits_;
  };

  size_t GetNumElements() const
  {
    assert(IsArrayTy() || IsStringTy());
    return IsStringTy() ? size_ : size_ / element_type_->size_;
  };

  const std::string GetName() const
  {
    assert(IsRecordTy());
    return name_;
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

  bool IsBoolTy() const
  {
    return type == Type::integer && size_bits_ == 1;
  };
  bool IsPtrTy() const
  {
    return type == Type::pointer;
  };
  bool IsIntTy() const
  {
    return type == Type::integer;
  };
  bool IsNoneTy(void) const
  {
    return type == Type::none;
  };
  bool IsIntegerTy(void) const
  {
    return type == Type::integer;
  };
  bool IsHistTy(void) const
  {
    return type == Type::hist;
  };
  bool IsLhistTy(void) const
  {
    return type == Type::lhist;
  };
  bool IsCountTy(void) const
  {
    return type == Type::count;
  };
  bool IsSumTy(void) const
  {
    return type == Type::sum;
  };
  bool IsMinTy(void) const
  {
    return type == Type::min;
  };
  bool IsMaxTy(void) const
  {
    return type == Type::max;
  };
  bool IsAvgTy(void) const
  {
    return type == Type::avg;
  };
  bool IsStatsTy(void) const
  {
    return type == Type::stats;
  };
  bool IsKstackTy(void) const
  {
    return type == Type::kstack;
  };
  bool IsUstackTy(void) const
  {
    return type == Type::ustack;
  };
  bool IsStringTy(void) const
  {
    return type == Type::string;
  };
  bool IsKsymTy(void) const
  {
    return type == Type::ksym;
  };
  bool IsUsymTy(void) const
  {
    return type == Type::usym;
  };
  bool IsProbeTy(void) const
  {
    return type == Type::probe;
  };
  bool IsUsernameTy(void) const
  {
    return type == Type::username;
  };
  bool IsInetTy(void) const
  {
    return type == Type::inet;
  };
  bool IsStackModeTy(void) const
  {
    return type == Type::stack_mode;
  };
  bool IsArrayTy(void) const
  {
    return type == Type::array;
  };
  bool IsRecordTy(void) const
  {
    return type == Type::record;
  };
  bool IsBufferTy(void) const
  {
    return type == Type::buffer;
  };
  bool IsTupleTy(void) const
  {
    return type == Type::tuple;
  };
  bool IsTimestampTy(void) const
  {
    return type == Type::timestamp;
  };
  bool IsMacAddressTy(void) const
  {
    return type == Type::mac_address;
  };

  friend std::ostream &operator<<(std::ostream &, const SizedType &);
  friend std::ostream &operator<<(std::ostream &, Type);

  // Factories

  friend SizedType CreateArray(size_t num_elements,
                               const SizedType &element_type);

  friend SizedType CreatePointer(const SizedType &pointee_type, AddrSpace as);
  friend SizedType CreateRecord(const std::string &name,
                                std::weak_ptr<Struct> record);
  friend SizedType CreateInteger(size_t bits, bool is_signed);
  friend SizedType CreateTuple(std::weak_ptr<Struct> tuple);
};
// Type helpers

SizedType CreateNone();
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

SizedType CreateString(size_t size);
SizedType CreateArray(size_t num_elements, const SizedType &element_type);
SizedType CreatePointer(const SizedType &pointee_type,
                        AddrSpace as = AddrSpace::none);

SizedType CreateRecord(const std::string &name, std::weak_ptr<Struct> record);
SizedType CreateTuple(std::weak_ptr<Struct> tuple);

SizedType CreateStackMode();
SizedType CreateStack(bool kernel, StackType st = StackType());

SizedType CreateMin(bool is_signed);
SizedType CreateMax(bool is_signed);
SizedType CreateSum(bool is_signed);
SizedType CreateCount(bool is_signed);
SizedType CreateAvg(bool is_signed);
SizedType CreateStats(bool is_signed);
SizedType CreateProbe();
SizedType CreateUsername();
SizedType CreateInet(size_t size);
SizedType CreateLhist();
SizedType CreateHist();
SizedType CreateUSym();
SizedType CreateKSym();
SizedType CreateBuffer(size_t size);
SizedType CreateTimestamp();
SizedType CreateMacAddress();

std::ostream &operator<<(std::ostream &os, const SizedType &type);

enum class ProbeType
{
  invalid,
  kprobe,
  kretprobe,
  uprobe,
  uretprobe,
  usdt,
  tracepoint,
  profile,
  interval,
  software,
  hardware,
  watchpoint,
  asyncwatchpoint,
  kfunc,
  kretfunc,
  iter,
};

std::ostream &operator<<(std::ostream &os, ProbeType type);

struct ProbeItem
{
  std::string name;
  std::string abbr;
  ProbeType type;
};

const std::vector<ProbeItem> PROBE_LIST = {
  { "kprobe", "k", ProbeType::kprobe },
  { "kretprobe", "kr", ProbeType::kretprobe },
  { "uprobe", "u", ProbeType::uprobe },
  { "uretprobe", "ur", ProbeType::uretprobe },
  { "usdt", "U", ProbeType::usdt },
  { "BEGIN", "BEGIN", ProbeType::uprobe },
  { "END", "END", ProbeType::uprobe },
  { "tracepoint", "t", ProbeType::tracepoint },
  { "profile", "p", ProbeType::profile },
  { "interval", "i", ProbeType::interval },
  { "software", "s", ProbeType::software },
  { "hardware", "h", ProbeType::hardware },
  { "watchpoint", "w", ProbeType::watchpoint },
  { "asyncwatchpoint", "aw", ProbeType::asyncwatchpoint },
  { "kfunc", "f", ProbeType::kfunc },
  { "kretfunc", "fr", ProbeType::kretfunc },
  { "iter", "it", ProbeType::iter },
};

ProbeType probetype(const std::string &type);
bool is_userspace_probe(const ProbeType &probe_type);
std::string addrspacestr(AddrSpace as);
std::string typestr(Type t);
std::string probetypeName(const std::string &type);
std::string probetypeName(ProbeType t);

struct Probe
{
  ProbeType type;
  std::string path;             // file path if used
  std::string attach_point;     // probe name (last component)
  std::string orig_name;        // original full probe name,
                                // before wildcard expansion
  std::string name;             // full probe name
  std::string pin;              // pin file for iterator probes
  std::string ns;               // for USDT probes, if provider namespace not from path
  uint64_t loc = 0;             // for USDT probes
  int usdt_location_idx = 0;    // to disambiguate duplicate USDT markers
  uint64_t log_size = 1000000;
  int index = 0;
  int freq = 0;
  pid_t pid = -1;
  uint64_t len = 0;             // for watchpoint probes, size of region
  std::string mode;             // for watchpoint probes, watch mode (rwx)
  bool async = false; // for watchpoint probes, if it's an async watchpoint
  uint64_t address = 0;
  uint64_t func_offset = 0;
};

const int RESERVED_IDS_PER_ASYNCACTION = 10000;

enum class AsyncAction
{
  // clang-format off
  printf  = 0,     // printf reserves 0-9999 for printf_ids
  syscall = 10000, // system reserves 10000-19999 for printf_ids
  cat     = 20000, // cat reserves 20000-29999 for printf_ids
  exit    = 30000,
  print,
  clear,
  zero,
  time,
  join,
  helper_error,
  print_non_map,
  strftime,
  watchpoint_attach,
  watchpoint_detach,
  // clang-format on
};

uint64_t asyncactionint(AsyncAction a);

enum class PositionalParameterType
{
  positional,
  count
};

} // namespace bpftrace

// SizedType hash function
// Allows to use SizedType in unordered_set/map.
namespace std {
template <>
struct hash<bpftrace::StackType>
{
  size_t operator()(const bpftrace::StackType &obj) const
  {
    switch (obj.mode)
    {
      case bpftrace::StackMode::bpftrace:
        return std::hash<std::string>()("bpftrace#" + to_string(obj.limit));
      case bpftrace::StackMode::perf:
        return std::hash<std::string>()("perf#" + to_string(obj.limit));
    }

    return {}; // unreached
  }
};

template <>
struct hash<bpftrace::SizedType>
{
  size_t operator()(const bpftrace::SizedType &type) const;
};

} // namespace std
