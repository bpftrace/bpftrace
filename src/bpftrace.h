#pragma once

#include <map>
#include <memory>
#include <vector>

#include "ast.h"
#include "map.h"

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
std::string typestr(ProbeType t);

class Probe
{
public:
  ProbeType type;
  std::string attach_point;
  int progfd;
};

class BPFtrace
{
public:
  int attach_probes();
  int add_probe(ast::Probe &p);

  std::map<std::string, Type> map_val_;
  std::map<std::string, std::vector<Type>> map_args_;
  std::map<std::string, std::unique_ptr<ebpf::bpftrace::Map>> maps_;

private:
  std::vector<Probe> probes_;

  int attach_kprobe(Probe &probe);
};

} // namespace bpftrace
} // namespace ebpf
