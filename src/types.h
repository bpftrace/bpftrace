#pragma once

#include <ostream>
#include <sstream>
#include <string>
#include <unistd.h>
#include <vector>

#include "libbpf.h"

namespace ebpf {
namespace bpftrace {

enum class Type
{
  none,
  integer,
  quantize,
  count,
};

std::ostream &operator<<(std::ostream &os, Type type);

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

template <typename T>
std::string argument_list(const std::vector<T> &items, size_t n, bool show_empty=false)
{
  if (n == 0)
  {
    if (show_empty)
      return "[]";
    return "";
  }

  std::ostringstream list;
  list << "[";
  for (size_t i = 0; i < n-1; i++)
    list << items.at(i) << ", ";
  list << items.at(n-1) << "]";
  return list.str();
}

template <typename T>
std::string argument_list(const std::vector<T> &items, bool show_empty=false)
{
  return argument_list(items, items.size(), show_empty);
}

} // namespace bpftrace
} // namespace ebpf
