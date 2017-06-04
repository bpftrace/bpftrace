#pragma once

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

enum class ProbeType
{
  kprobe,
  kretprobe,
};

std::string typestr(Type t);
bpf_probe_attach_type attachtype(ProbeType t);
bpf_prog_type progtype(ProbeType t);
std::string argument_list(const std::vector<uint64_t> &items);
std::string argument_list(const std::vector<uint64_t> &items, size_t n);

class Probe
{
public:
  ProbeType type;
  std::string attach_point;
  std::string name;
};

} // namespace bpftrace
} // namespace ebpf
