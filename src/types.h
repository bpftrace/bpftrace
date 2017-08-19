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
  del,
  integer,
  quantize,
  count,
  stack,
  ustack,
  string,
  sym,
  usym,
};

std::ostream &operator<<(std::ostream &os, Type type);

class SizedType
{
public:
  SizedType() : type(Type::none), size(0) { }
  SizedType(Type type, size_t size) : type(type), size(size) { }
  Type type;
  size_t size;

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
};

} // namespace bpftrace
