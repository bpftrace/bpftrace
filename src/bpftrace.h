#pragma once

#include <map>
#include <memory>
#include <vector>

#include "libbpf.h"
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
bpf_probe_attach_type attachtype(ProbeType t);
bpf_prog_type progtype(ProbeType t);

class Probe
{
public:
  ProbeType type;
  std::string attach_point;
  std::string name;
  int progfd;
  bool attached = false;
};

class BPFtrace
{
public:
  virtual ~BPFtrace() { }
  int load_progs();
  int attach_probes();
  int detach_probes();
  virtual int add_probe(ast::Probe &p);

  std::map<std::string, Type> map_val_;
  std::map<std::string, std::vector<Type>> map_args_;
  std::map<std::string, std::unique_ptr<ebpf::bpftrace::Map>> maps_;
  std::map<std::string, std::tuple<uint8_t *, uintptr_t>> sections_;

private:
  std::vector<Probe> probes_;

  int attach_kprobe(Probe &probe);

  static std::string eventname(Probe &probe);
};

} // namespace bpftrace
} // namespace ebpf
