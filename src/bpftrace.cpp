#include <iostream>

#include "bpftrace.h"

namespace ebpf {
namespace bpftrace {

std::string typestr(Type t)
{
  switch (t)
  {
    case Type::none:     return "none";     break;
    case Type::integer:  return "integer";  break;
    case Type::quantize: return "quantize"; break;
    case Type::count:    return "count";    break;
    default: abort();
  }
}

std::string typestr(ProbeType t)
{
  switch (t)
  {
    case ProbeType::kprobe:    return "kprobe";    break;
    case ProbeType::kretprobe: return "kretprobe"; break;
    default: abort();
  }
}

int BPFtrace::attach_probes()
{
  for (Probe &probe : probes_) {
    int err = 0;
    switch (probe.type)
    {
      case ProbeType::kprobe:
      case ProbeType::kretprobe:
        err = attach_kprobe(probe);
        break;
      default:
        abort();
    }

    if (err) {
      std::cerr << "Error attaching probe: " << typestr(probe.type) << ":" << probe.attach_point << std::endl;
      return err;
    }

    probe.attached = true;
  }
  return 0;
}

int BPFtrace::detach_probes()
{
  int result = 0;
  for (Probe &probe : probes_) {
    if (!probe.attached)
      continue;

    int err = 0;
    switch (probe.type)
    {
      case ProbeType::kprobe:
      case ProbeType::kretprobe:
        err = bpf_detach_kprobe(eventname(probe).c_str());
        break;
      default:
        abort();
    }

    if (err) {
      std::cerr << "Error detaching probe: " << typestr(probe.type) << ":" << probe.attach_point << std::endl;
      result = err;
    }
  }
  return result;
}

int BPFtrace::add_probe(ast::Probe &p)
{
  Probe probe;
  probe.attach_point = p.attach_point;
  if (p.type == "kprobe") {
    probe.type = ProbeType::kprobe;
  }
  else if (p.type == "kretprobe") {
    probe.type = ProbeType::kretprobe;
  }
  else {
    return -1;
  }
  probes_.push_back(probe);
  return 0;
}

int BPFtrace::attach_kprobe(Probe &probe)
{
  int pid = -1;
  int cpu = 0;
  int group_fd = -1;
  perf_reader_cb cb = nullptr;
  void *cb_cookie = nullptr;

  void *result = bpf_attach_kprobe(probe.progfd, attachtype(probe),
      eventname(probe).c_str(), probe.attach_point.c_str(),
      pid, cpu, group_fd, cb, cb_cookie);

  if (result == nullptr)
    return 1;
  return 0;
}

std::string BPFtrace::eventname(Probe &probe)
{
  std::string event;
  switch (probe.type) {
    case ProbeType::kprobe:
      event =  "p_" + probe.attach_point;
      break;
    case ProbeType::kretprobe:
      event =  "r_" + probe.attach_point;
      break;
    default:
      abort();
  }
  return event;
}

bpf_probe_attach_type BPFtrace::attachtype(Probe &probe)
{
  bpf_probe_attach_type attach_type;
  switch (probe.type) {
    case ProbeType::kprobe:
      attach_type = BPF_PROBE_ENTRY;
      break;
    case ProbeType::kretprobe:
      attach_type = BPF_PROBE_RETURN;
      break;
    default:
      abort();
  }
  return attach_type;
}

} // namespace bpftrace
} // namespace ebpf
