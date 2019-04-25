#pragma once

#include <ostream>
#include <sstream>
#include <string>
#include <vector>
#include <unistd.h>

namespace bpftrace {

const int MAX_STACK_SIZE = 1024;
const int DEFAULT_STACK_SIZE = 127;
const int STRING_SIZE = 64;
const int COMM_SIZE = 16;

enum class Type
{
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

class SizedType
{
public:
  SizedType() : type(Type::none), size(0) { }
  SizedType(Type type, size_t size_, const std::string &cast_type = "")
    : type(type), size(size_), cast_type(cast_type) { }
  SizedType(Type type, StackType stack_type_)
    : SizedType(type, 8) {
    stack_type = stack_type_;
  }
  Type type;
  Type elem_type; // Array element type if accessing elements of an array
  size_t size;
  StackType stack_type;
  std::string cast_type;
  bool is_internal = false;
  bool is_pointer = false;
  bool is_tparg = false;
  size_t pointee_size;

  bool IsArray() const;
  bool IsStack() const;

  bool operator==(const SizedType &t) const;
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
  { "hardware", "h", ProbeType::hardware }
};

std::string typestr(Type t);
ProbeType probetype(const std::string &type);
std::string probetypeName(const std::string &type);
std::string probetypeName(ProbeType t);

class Probe
{
public:
  ProbeType type;
  std::string path;		// file path if used
  std::string attach_point;	// probe name (last component)
  std::string orig_name;	// original full probe name,
				// before wildcard expansion
  std::string name;		// full probe name
  std::string ns;		// for USDT probes, if provider namespace not from path
  uint64_t loc;			// for USDT probes
  int index = 0;
  int freq;
};

enum class AsyncAction
{
  // printf reserves 0-9999 for printf_ids
  syscall = 10000, // system reserves 10000-19999 for printf_ids
  exit = 20000,
  print,
  clear,
  zero,
  time,
  join,
  cat
};

uint64_t asyncactionint(AsyncAction a);

} // namespace bpftrace


namespace std {
template<>
struct hash<bpftrace::StackType>
{
  size_t operator()(const bpftrace::StackType& obj) const
  {
    switch (obj.mode) {
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
}
