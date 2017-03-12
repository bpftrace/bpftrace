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

bpf_probe_attach_type attachtype(ProbeType t)
{
  switch (t)
  {
    case ProbeType::kprobe:    return BPF_PROBE_ENTRY;  break;
    case ProbeType::kretprobe: return BPF_PROBE_RETURN; break;
    default: abort();
  }
}

bpf_prog_type progtype(ProbeType t)
{
  switch (t)
  {
    case ProbeType::kprobe:    return BPF_PROG_TYPE_KPROBE; break;
    case ProbeType::kretprobe: return BPF_PROG_TYPE_KPROBE; break;
    default: abort();
  }
}

int BPFtrace::load_progs()
{
  for (Probe &probe : probes_)
  {
    auto func = sections_.find(probe.name);
    if (func == sections_.end())
      return -1;

    uint8_t *insns = std::get<0>(func->second);
    int prog_len = std::get<1>(func->second);
    const char *license = "mylicencehere";
    unsigned kern_version = (4 << 16) | (10 << 8) | 1;
    char *log_buf = nullptr;
    unsigned log_buf_size = 0;
    probe.progfd = bpf_prog_load(progtype(probe.type),
        reinterpret_cast<struct bpf_insn*>(insns), prog_len,
        license, kern_version, log_buf, log_buf_size);

    if (probe.progfd < 0)
    {
      std::cerr << "Error loading program: " << probe.name << std::endl;
      return probe.progfd;
    }
  }
  return 0;
}

int BPFtrace::attach_probes()
{
  for (Probe &probe : probes_)
  {
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

    probe.attached = true;

    if (err)
    {
      std::cerr << "Error attaching probe: " << probe.name << std::endl;
      return err;
    }
  }
  return 0;
}

int BPFtrace::detach_probes()
{
  int result = 0;
  for (Probe &probe : probes_)
  {
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

    if (err)
    {
      std::cerr << "Error detaching probe: " << probe.name << std::endl;
      result = err;
    }
  }
  return result;
}

int BPFtrace::add_probe(ast::Probe &p)
{
  Probe probe;
  probe.attach_point = p.attach_point;
  probe.name = p.name;
  if (p.type == "kprobe")
    probe.type = ProbeType::kprobe;
  else if (p.type == "kretprobe")
    probe.type = ProbeType::kretprobe;
  else
    return -1;
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

  void *result = bpf_attach_kprobe(probe.progfd, attachtype(probe.type),
      eventname(probe).c_str(), probe.attach_point.c_str(),
      pid, cpu, group_fd, cb, cb_cookie);

  if (result == nullptr)
    return -1;
  return 0;
}

std::string BPFtrace::eventname(Probe &probe)
{
  std::string event;
  switch (probe.type)
  {
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

} // namespace bpftrace
} // namespace ebpf
