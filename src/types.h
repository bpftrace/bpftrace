#pragma once

#include <ostream>
#include <sstream>
#include <string>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

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
  cast,
  join,
  probe,
  username,
  inet,
  stack_mode,
  array,
  // BPF program context; needing a different access method to satisfy the verifier
  ctx,
  buffer,
  // clang-format on
};

std::ostream &operator<<(std::ostream &os, Type type);

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
};

struct SizedType
{
  SizedType() : type(Type::none), size(0) { }
  SizedType(Type type,
            size_t size_,
            bool is_signed,
            const std::string &cast_type = "")
      : type(type), size(size_), is_signed(is_signed), cast_type(cast_type)
  {
  }
  SizedType(Type type, size_t size_, const std::string &cast_type = "")
      : type(type), size(size_), cast_type(cast_type)
  {
  }

  SizedType(Type type, StackType stack_type_) : SizedType(type, 8)
  {
    stack_type = stack_type_;
  }
  Type type;
  Type elem_type = Type::none; // Array element type if accessing elements of an
                               // array
  size_t size;
  StackType stack_type;
  bool is_signed = false;
  std::string cast_type;
  bool is_internal = false;
  bool is_pointer = false;
  bool is_tparg = false;
  bool is_kfarg = false;
  size_t pointee_size = 0;
  int kfarg_idx = -1;

  bool IsArray() const;
  bool IsStack() const;

  bool IsEqual(const SizedType &t) const;
  bool operator==(const SizedType &t) const;
  bool operator!=(const SizedType &t) const;
};

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
  kfunc,
  kretfunc,
};

struct ProbeItem
{
  std::string name;
  std::string abbr;
  ProbeType type;
};

const std::vector<ProbeItem> PROBE_LIST =
{
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
  { "kfunc", "f", ProbeType::kfunc },
  { "kretfunc", "fr", ProbeType::kretfunc },
};

std::string typestr(Type t);
ProbeType probetype(const std::string &type);
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
  std::string ns;               // for USDT probes, if provider namespace not from path
  uint64_t loc;                 // for USDT probes
  uint64_t log_size;
  int index = 0;
  int freq;
  pid_t pid = -1;
  uint64_t len = 0;             // for watchpoint probes, size of region
  std::string mode;             // for watchpoint probes, watch mode (rwx)
  uint64_t address = 0;
  uint64_t func_offset = 0;
};

const int RESERVED_IDS_PER_ASYNCACTION = 10000;

enum class AsyncAction
{
  printf  = 0,     // printf reserves 0-9999 for printf_ids
  syscall = 10000, // system reserves 10000-19999 for printf_ids
  cat     = 20000, // cat reserves 20000-29999 for printf_ids
  exit    = 30000,
  print,
  clear,
  zero,
  time,
  join,
};

uint64_t asyncactionint(AsyncAction a);

enum class PositionalParameterType
{
  positional,
  count
};

} // namespace bpftrace

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
      // TODO (mmarchini): enable -Wswitch-enum and disable -Wswitch-default
      default:
        abort();
    }
  }
};
} // namespace std
