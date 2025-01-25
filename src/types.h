#pragma once

#include <cassert>
#include <map>
#include <memory>
#include <optional>
#include <ostream>
#include <sstream>
#include <string>
#include <sys/types.h>
#include <unistd.h>
#include <unordered_set>
#include <vector>

#include <cereal/access.hpp>

namespace bpftrace {

const int MAX_STACK_SIZE = 1024;
const int DEFAULT_STACK_SIZE = 127;
const int COMM_SIZE = 16;

enum class Type : uint8_t {
  // clang-format off
  none,
  voidtype,
  integer, // int is a protected keyword
  pointer,
  reference,
  record, // struct/union, as struct is a protected keyword
  hist_t,
  lhist_t,
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
  strerror_t,
  timestamp_mode,
  // clang-format on
};

enum class AddrSpace : uint8_t {
  none,
  kernel,
  user,
  bpf,
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

struct StackType {
  uint16_t limit = DEFAULT_STACK_SIZE;
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
  bool is_tparg = false;
  bool is_funcarg = false;
  bool is_btftype = false;
  TimestampMode ts_mode = TimestampMode::boot;

private:
  Type type_;
  size_t size_bits_ = 0;                    // size in bits
  std::shared_ptr<SizedType> element_type_; // for "container" and pointer
                                            // (like) types
  std::string name_; // name of this type, for named types like struct and enum
  std::weak_ptr<Struct> inner_struct_; // inner struct for records and tuples
                                       // the actual Struct object is owned by
                                       // StructManager
  AddrSpace as_ = AddrSpace::none;
  bool is_signed_ = false;
  bool ctx_ = false;                                   // Is bpf program context
  std::unordered_set<std::string> btf_type_tags_ = {}; // Only populated for
                                                       // Type::pointer
  size_t num_elements_ = 0; // Only populated for array types

  friend class cereal::access;
  template <typename Archive>
  void serialize(Archive &archive)
  {
    archive(type_,
            stack_type,
            is_internal,
            is_tparg,
            is_funcarg,
            is_btftype,
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
  std::weak_ptr<const Struct> GetStruct() const;

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
  bool operator!=(const SizedType &t) const;
  bool IsSameType(const SizedType &t) const;
  // This is primarily for Tuples which have equal total size (due to padding)
  // but their individual elements have different sizes.
  bool IsSameSizeRecursive(const SizedType &t) const;
  bool FitsInto(const SizedType &t) const;

  bool IsPrintableTy()
  {
    return type_ != Type::none && type_ != Type::stack_mode &&
           type_ != Type::timestamp_mode &&
           (!IsCtxAccess() || is_funcarg); // args builtin is printable
  }

  void SetSign(bool is_signed)
  {
    is_signed_ = is_signed;
  }

  bool IsSigned(void) const;

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
    if (bits > 64)
      bits = 64;
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

  const std::string GetName() const
  {
    assert(IsRecordTy() || IsEnumTy());
    return name_;
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

  const SizedType *GetDereferencedTy() const
  {
    assert(IsRefTy());
    return element_type_.get();
  }

  bool IsBoolTy() const
  {
    return type_ == Type::integer && size_bits_ == 1;
  };
  bool IsPtrTy() const
  {
    return type_ == Type::pointer;
  };
  bool IsRefTy() const
  {
    return type_ == Type::reference;
  };
  bool IsIntTy() const
  {
    return type_ == Type::integer;
  };
  bool IsEnumTy() const
  {
    return IsIntTy() && name_.size();
  }
  bool IsNoneTy(void) const
  {
    return type_ == Type::none;
  };
  bool IsVoidTy(void) const
  {
    return type_ == Type::voidtype;
  };
  bool IsIntegerTy(void) const
  {
    return type_ == Type::integer;
  };
  bool IsHistTy(void) const
  {
    return type_ == Type::hist_t;
  };
  bool IsLhistTy(void) const
  {
    return type_ == Type::lhist_t;
  };
  bool IsCountTy(void) const
  {
    return type_ == Type::count_t;
  };
  bool IsSumTy(void) const
  {
    return type_ == Type::sum_t;
  };
  bool IsMinTy(void) const
  {
    return type_ == Type::min_t;
  };
  bool IsMaxTy(void) const
  {
    return type_ == Type::max_t;
  };
  bool IsAvgTy(void) const
  {
    return type_ == Type::avg_t;
  };
  bool IsStatsTy(void) const
  {
    return type_ == Type::stats_t;
  };
  bool IsKstackTy(void) const
  {
    return type_ == Type::kstack_t;
  };
  bool IsUstackTy(void) const
  {
    return type_ == Type::ustack_t;
  };
  bool IsStringTy(void) const
  {
    return type_ == Type::string;
  };
  bool IsKsymTy(void) const
  {
    return type_ == Type::ksym_t;
  };
  bool IsUsymTy(void) const
  {
    return type_ == Type::usym_t;
  };
  bool IsUsernameTy(void) const
  {
    return type_ == Type::username;
  };
  bool IsInetTy(void) const
  {
    return type_ == Type::inet;
  };
  bool IsStackModeTy(void) const
  {
    return type_ == Type::stack_mode;
  };
  bool IsArrayTy(void) const
  {
    return type_ == Type::array;
  };
  bool IsRecordTy(void) const
  {
    return type_ == Type::record;
  };
  bool IsBufferTy(void) const
  {
    return type_ == Type::buffer;
  };
  bool IsTupleTy(void) const
  {
    return type_ == Type::tuple;
  };
  bool IsTimestampTy(void) const
  {
    return type_ == Type::timestamp;
  };
  bool IsMacAddressTy(void) const
  {
    return type_ == Type::mac_address;
  };
  bool IsCgroupPathTy(void) const
  {
    return type_ == Type::cgroup_path_t;
  };
  bool IsStrerrorTy(void) const
  {
    return type_ == Type::strerror_t;
  };
  bool IsTimestampModeTy(void) const
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
    return !IsMultiOutputMapTy();
  }

  // These are special map value types that can't be reduced to a single value
  // and output multiple lines when printed
  bool IsMultiOutputMapTy() const
  {
    return type_ == Type::hist_t || type_ == Type::lhist_t ||
           type_ == Type::stats_t;
  }

  bool NeedsPercpuMap() const;

  friend std::string typestr(const SizedType &type);

  void IntoPointer()
  {
    assert(IsRefTy());
    type_ = Type::pointer;
  }

  // Factories

  friend SizedType CreateEnum(size_t bits, const std::string &name);
  friend SizedType CreateArray(size_t num_elements,
                               const SizedType &element_type);

  friend SizedType CreatePointer(const SizedType &pointee_type, AddrSpace as);
  friend SizedType CreateReference(const SizedType &pointee_type, AddrSpace as);
  friend SizedType CreateRecord(const std::string &name,
                                std::weak_ptr<Struct> record);
  friend SizedType CreateInteger(size_t bits, bool is_signed);
  friend SizedType CreateTuple(std::weak_ptr<Struct> tuple);
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

SizedType CreateString(size_t size);
SizedType CreateArray(size_t num_elements, const SizedType &element_type);
SizedType CreatePointer(const SizedType &pointee_type,
                        AddrSpace as = AddrSpace::none);
SizedType CreateReference(const SizedType &referred_type,
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
SizedType CreateUsername();
SizedType CreateInet(size_t size);
SizedType CreateLhist();
SizedType CreateHist();
SizedType CreateUSym();
SizedType CreateKSym();
SizedType CreateBuffer(size_t size);
SizedType CreateTimestamp();
SizedType CreateMacAddress();
SizedType CreateCgroupPath();
SizedType CreateStrerror();
SizedType CreateTimestampMode();

std::ostream &operator<<(std::ostream &os, const SizedType &type);

enum class ProbeType {
  invalid,
  special,
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
  fentry,
  fexit,
  iter,
  rawtracepoint,
};

std::ostream &operator<<(std::ostream &os, ProbeType type);

struct ProbeItem {
  std::string name;
  std::unordered_set<std::string> aliases;
  ProbeType type;
  // these are used in bpftrace -l
  // to show which probes are available to attach to
  bool show_in_kernel_list = false;
  bool show_in_userspace_list = false;
};

const std::vector<ProbeItem> PROBE_LIST = {
  { .name = "kprobe",
    .aliases = { "k" },
    .type = ProbeType::kprobe,
    .show_in_kernel_list = true },
  { .name = "kretprobe", .aliases = { "kr" }, .type = ProbeType::kretprobe },
  { .name = "uprobe",
    .aliases = { "u" },
    .type = ProbeType::uprobe,
    .show_in_userspace_list = true },
  { .name = "uretprobe", .aliases = { "ur" }, .type = ProbeType::uretprobe },
  { .name = "usdt",
    .aliases = { "U" },
    .type = ProbeType::usdt,
    .show_in_userspace_list = true },
  { .name = "BEGIN", .aliases = { "BEGIN" }, .type = ProbeType::special },
  { .name = "END", .aliases = { "END" }, .type = ProbeType::special },
  { .name = "self", .aliases = { "self" }, .type = ProbeType::special },
  { .name = "tracepoint",
    .aliases = { "t" },
    .type = ProbeType::tracepoint,
    .show_in_kernel_list = true },
  { .name = "profile", .aliases = { "p" }, .type = ProbeType::profile },
  { .name = "interval", .aliases = { "i" }, .type = ProbeType::interval },
  { .name = "software",
    .aliases = { "s" },
    .type = ProbeType::software,
    .show_in_kernel_list = true },
  { .name = "hardware",
    .aliases = { "h" },
    .type = ProbeType::hardware,
    .show_in_kernel_list = true },
  { .name = "watchpoint", .aliases = { "w" }, .type = ProbeType::watchpoint },
  { .name = "asyncwatchpoint",
    .aliases = { "aw" },
    .type = ProbeType::asyncwatchpoint },
  { .name = "fentry",
    .aliases = { "f", "kfunc" },
    .type = ProbeType::fentry,
    .show_in_kernel_list = true },
  { .name = "fexit",
    .aliases = { "fr", "kretfunc" },
    .type = ProbeType::fexit },
  { .name = "iter",
    .aliases = { "it" },
    .type = ProbeType::iter,
    .show_in_kernel_list = true },
  { .name = "rawtracepoint",
    .aliases = { "rt" },
    .type = ProbeType::rawtracepoint,
    .show_in_kernel_list = true },
};

ProbeType probetype(const std::string &type);
std::string addrspacestr(AddrSpace as);
std::string typestr(Type t);
std::string typestr(const SizedType &type);
std::string expand_probe_name(const std::string &orig_name);
std::string probetypeName(ProbeType t);

struct Probe {
  ProbeType type;
  std::string path;         // file path if used
  std::string attach_point; // probe name (last component)
  std::string orig_name;    // original full probe name,
                            // before wildcard expansion
  std::string name;         // full probe name
  bool need_expansion;
  std::string pin;  // pin file for iterator probes
  std::string ns;   // for USDT probes, if provider namespace not from path
  uint64_t loc = 0; // for USDT probes
  int usdt_location_idx = 0; // to disambiguate duplicate USDT markers
  uint64_t log_size = 1000000;
  int index = 0;
  int freq = 0;
  uint64_t len = 0;   // for watchpoint probes, size of region
  std::string mode;   // for watchpoint probes, watch mode (rwx)
  bool async = false; // for watchpoint probes, if it's an async watchpoint
  uint64_t address = 0;
  uint64_t func_offset = 0;
  std::vector<std::string> funcs;

private:
  friend class cereal::access;
  template <typename Archive>
  void serialize(Archive &archive)
  {
    archive(type,
            path,
            attach_point,
            orig_name,
            name,
            pin,
            ns,
            loc,
            usdt_location_idx,
            log_size,
            index,
            freq,
            len,
            mode,
            async,
            address,
            func_offset,
            funcs);
  }
};

const int RESERVED_IDS_PER_ASYNCACTION = 10000;

enum class AsyncAction {
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
  skboutput,
  // clang-format on
};

uint64_t asyncactionint(AsyncAction a);

enum class PositionalParameterType { positional, count };

namespace globalvars {

enum class GlobalVar {
  // Number of online CPUs at runtime, used for metric aggregation for functions
  // like sum and avg
  NUM_CPUS,
  // Max CPU ID returned by bpf_get_smp_processor_id, used for simulating
  // per-CPU maps in read-write global variables
  MAX_CPU_ID,
  // Scratch buffers used to avoid BPF stack allocation limits
  FMT_STRINGS_BUFFER,
  TUPLE_BUFFER,
  GET_STR_BUFFER,
  READ_MAP_VALUE_BUFFER,
  WRITE_MAP_VALUE_BUFFER,
  VARIABLE_BUFFER,
  MAP_KEY_BUFFER,
};

} // namespace globalvars

} // namespace bpftrace

// SizedType hash function
// Allows to use SizedType in unordered_set/map.
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

template <>
struct hash<bpftrace::SizedType> {
  size_t operator()(const bpftrace::SizedType &type) const;
};

} // namespace std
