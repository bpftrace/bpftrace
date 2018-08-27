#pragma once

#include <ostream>
#include <sstream>
#include <string>
#include <vector>
#include <unistd.h>

namespace bpftrace {

const int MAX_STACK_SIZE = 32;
const int STRING_SIZE = 64;

enum class Type
{
  none,
  integer,
  quantize,
  count,
  stack,
  ustack,
  string,
  sym,
  usym,
  cast,
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
  std::string path;
  std::string attach_point;
  std::string prog_name;
  std::string name;
  int freq;
};

enum class AsyncAction
{
  // printf reserves 0-9999 for printf_ids
  exit = 10000,
  print,
  clear,
  zero,
  time,
};

uint64_t asyncactionint(AsyncAction a);

} // namespace bpftrace
