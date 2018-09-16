#pragma once

#include <ostream>
#include <sstream>
#include <string>
#include <vector>
#include <unistd.h>

namespace bpftrace {

const int MAX_STACK_SIZE = 32;
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
  stack,
  ustack,
  string,
  sym,
  usym,
  cast,
  join,
  name,
  username,
};

std::ostream &operator<<(std::ostream &os, Type type);

class SizedType
{
public:
  SizedType() : type(Type::none), size(0) { }
  SizedType(Type type, size_t size, const std::string &cast_type = "")
    : type(type), size(size), cast_type(cast_type) { }
  Type type;
  size_t size;
  std::string cast_type;
  bool is_internal = false;
  bool is_pointer = false;
  size_t pointee_size;

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

std::string typestr(Type t);
ProbeType probetype(const std::string &type);

class Probe
{
public:
  ProbeType type;
  std::string path;		// file path if used
  std::string attach_point;	// probe name (last component)
  std::string orig_name;	// original full probe name,
				// before wildcard expansion
  std::string name;		// full probe name
  uint64_t loc;			// for USDT probes
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
};

uint64_t asyncactionint(AsyncAction a);

} // namespace bpftrace
