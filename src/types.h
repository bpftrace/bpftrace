#pragma once

#include <ostream>
#include <sstream>
#include <string>
#include <vector>
#include <unistd.h>

#include "libbpf.h"

namespace bpftrace {

const int MAX_STACK_SIZE = 32;

enum class Type
{
  none,
  integer,
  quantize,
  count,
  stack,
};

std::ostream &operator<<(std::ostream &os, Type type);

class MapKeyArgument
{
public:
  Type type;
  size_t size;

  bool operator==(const MapKeyArgument &a) const;
};

std::ostream &operator<<(std::ostream &os, MapKeyArgument arg);

enum class ProbeType
{
  kprobe,
  kretprobe,
};

std::string typestr(Type t);
bpf_probe_attach_type attachtype(ProbeType t);
bpf_prog_type progtype(ProbeType t);

class Probe
{
public:
  ProbeType type;
  std::string attach_point;
  std::string name;
};

} // namespace bpftrace
