#include <iostream>

#include "bpftrace.h"
#include "libbpf.h"

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
  int err = 0;
  for (Probe &probe : probes_) {
    if (probe.type == ProbeType::kprobe ||
        probe.type == ProbeType::kretprobe) {
      err = attach_kprobe(probe);
    }
    else {
      abort();
    }

    if (err) {
      std::cerr << "Error attaching probe: " << typestr(probe.type) << ":" << probe.attach_point << std::endl;
      return err;
    }
  }
  return 0;
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
  std::string event;
  std::string event_desc;
  int pid = -1;
  int cpu = 0;
  int group_fd = -1;
  perf_reader_cb cb = nullptr;
  void *cb_cookie = nullptr;

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

  switch (probe.type) {
    case ProbeType::kprobe:
      event_desc =  "p:kprobes/" + event + " " + probe.attach_point;
      break;
    case ProbeType::kretprobe:
      event_desc =  "r:kprobes/" + event + " " + probe.attach_point;
      break;
    default:
      abort();
  }

  bpf_attach_kprobe(probe.progfd, event.c_str(), event_desc.c_str(),
      pid, cpu, group_fd, cb, cb_cookie);
}

} // namespace bpftrace
} // namespace ebpf
