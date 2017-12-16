#include <iostream>
#include <regex>
#include <sys/utsname.h>
#include <tuple>
#include <unistd.h>

#include "attached_probe.h"
#include "bcc_syms.h"
#include "common.h"
#include "libbpf.h"
#include "perf_reader.h"
#include <linux/perf_event.h>

namespace bpftrace {

bpf_probe_attach_type attachtype(ProbeType t)
{
  switch (t)
  {
    case ProbeType::kprobe:    return BPF_PROBE_ENTRY;  break;
    case ProbeType::kretprobe: return BPF_PROBE_RETURN; break;
    case ProbeType::uprobe:    return BPF_PROBE_ENTRY;  break;
    case ProbeType::uretprobe: return BPF_PROBE_RETURN; break;
    default: abort();
  }
}

bpf_prog_type progtype(ProbeType t)
{
  switch (t)
  {
    case ProbeType::kprobe:     return BPF_PROG_TYPE_KPROBE; break;
    case ProbeType::kretprobe:  return BPF_PROG_TYPE_KPROBE; break;
    case ProbeType::uprobe:     return BPF_PROG_TYPE_KPROBE; break;
    case ProbeType::uretprobe:  return BPF_PROG_TYPE_KPROBE; break;
    case ProbeType::tracepoint: return BPF_PROG_TYPE_TRACEPOINT; break;
    case ProbeType::profile:      return BPF_PROG_TYPE_PERF_EVENT; break;
    default: abort();
  }
}


AttachedProbe::AttachedProbe(Probe &probe, std::tuple<uint8_t *, uintptr_t> &func)
  : probe_(probe), func_(func)
{
  load_prog();
  switch (probe_.type)
  {
    case ProbeType::kprobe:
    case ProbeType::kretprobe:
      attach_kprobe();
      break;
    case ProbeType::uprobe:
    case ProbeType::uretprobe:
      attach_uprobe();
      break;
    case ProbeType::tracepoint:
      attach_tracepoint();
      break;
    case ProbeType::profile:
      attach_profile();
      break;
    default:
      abort();
  }
}

AttachedProbe::~AttachedProbe()
{
  close(progfd_);
  if (perf_reader_)
    perf_reader_free(perf_reader_);
  int err = 0;
  switch (probe_.type)
  {
    case ProbeType::kprobe:
    case ProbeType::kretprobe:
      err = bpf_detach_kprobe(eventname().c_str());
      break;
    case ProbeType::uprobe:
    case ProbeType::uretprobe:
      err = bpf_detach_uprobe(eventname().c_str());
      break;
    case ProbeType::tracepoint:
      err = bpf_detach_tracepoint(probe_.path.c_str(), eventname().c_str());
      break;
    case ProbeType::profile:
      err = detach_profile();
      break;
    default:
      abort();
  }
  if (err)
    std::cerr << "Error detaching probe: " << probe_.name << std::endl;
}

std::string AttachedProbe::eventprefix() const
{
  switch (attachtype(probe_.type))
  {
    case BPF_PROBE_ENTRY:
      return "p_";
    case BPF_PROBE_RETURN:
      return "r_";
    default:
      abort();
  }
}

std::string AttachedProbe::eventname() const
{
  std::ostringstream offset_str;
  switch (probe_.type)
  {
    case ProbeType::kprobe:
    case ProbeType::kretprobe:
      return eventprefix() + probe_.attach_point;
    case ProbeType::uprobe:
    case ProbeType::uretprobe:
      offset_str << std::hex << offset();
      return eventprefix() + sanitise(probe_.path) + "_" + offset_str.str();
    case ProbeType::tracepoint:
      return probe_.attach_point;
    default:
      abort();
  }
}

std::string AttachedProbe::sanitise(const std::string &str)
{
  return std::regex_replace(str, std::regex("[^A-Za-z0-9_]"), "_");
}

uint64_t AttachedProbe::offset() const
{
  bcc_symbol sym;
  int err = bcc_resolve_symname(probe_.path.c_str(), probe_.attach_point.c_str(),
      0, 0, nullptr, &sym);

  if (err)
    throw std::runtime_error("Could not resolve symbol: " + probe_.path + ":" + probe_.attach_point);

  return sym.offset;
}

static unsigned kernel_version()
{
  struct utsname utsname;
  uname(&utsname);
  unsigned x, y, z;
  sscanf(utsname.release, "%d.%d.%d", &x, &y, &z);
  return (x << 16) + (y << 8) + z;
}

void AttachedProbe::load_prog()
{
  uint8_t *insns = std::get<0>(func_);
  int prog_len = std::get<1>(func_);
  const char *license = "GPL";
  unsigned kern_version = kernel_version();
  int log_level = 0;
  char *log_buf = nullptr;
  unsigned log_buf_size = 0;

  progfd_ = bpf_prog_load(progtype(probe_.type), probe_.name.c_str(),
      reinterpret_cast<struct bpf_insn*>(insns), prog_len,
      license, kern_version, log_level, log_buf, log_buf_size);

  if (progfd_ < 0)
    throw std::runtime_error("Error loading program: " + probe_.name);
}

void AttachedProbe::attach_kprobe()
{
  perf_reader_cb cb = nullptr;
  void *cb_cookie = nullptr;

  perf_reader_ = bpf_attach_kprobe(progfd_, attachtype(probe_.type),
      eventname().c_str(), probe_.attach_point.c_str(), cb, cb_cookie);

  if (perf_reader_ == nullptr)
    throw std::runtime_error("Error attaching probe: '" + probe_.name + "'");
}

void AttachedProbe::attach_uprobe()
{
  int pid = -1;
  perf_reader_cb cb = nullptr;
  void *cb_cookie = nullptr;

  perf_reader_ = bpf_attach_uprobe(progfd_, attachtype(probe_.type),
      eventname().c_str(), probe_.path.c_str(), offset(), pid, cb, cb_cookie);

  if (perf_reader_ == nullptr)
    throw std::runtime_error("Error attaching probe: " + probe_.name);
}

void AttachedProbe::attach_tracepoint()
{
  perf_reader_cb cb = nullptr;
  void *cb_cookie = nullptr;

  perf_reader_ = bpf_attach_tracepoint(progfd_, probe_.path.c_str(),
      eventname().c_str(), cb, cb_cookie);

  if (perf_reader_ == nullptr)
    throw std::runtime_error("Error attaching probe: " + probe_.name);
}

void AttachedProbe::attach_profile()
{
  int pid = -1;
  int group_fd = -1;

  uint64_t period, freq;
  if (probe_.path == "hz")
  {
    period = 0;
    freq = probe_.freq;
  }
  else if (probe_.path == "s")
  {
    period = probe_.freq * 1e9;
    freq = 0;
  }
  else if (probe_.path == "ms")
  {
    period = probe_.freq * 1e6;
    freq = 0;
  }
  else if (probe_.path == "us")
  {
    period = probe_.freq * 1e3;
    freq = 0;
  }
  else
  {
    abort();
  }

  std::vector<int> cpus = ebpf::get_online_cpus();
  for (int cpu : cpus)
  {
    int perf_event_fd = bpf_attach_perf_event(progfd_, PERF_TYPE_SOFTWARE,
        PERF_COUNT_SW_CPU_CLOCK, period, freq, pid, cpu, group_fd);

    if (perf_event_fd < 0)
      throw std::runtime_error("Error attaching probe: " + probe_.name);

    perf_event_fds_.push_back(perf_event_fd);
  }
}

int AttachedProbe::detach_profile()
{
  for (int perf_event_fd : perf_event_fds_)
  {
    int err = bpf_close_perf_event_fd(perf_event_fd);
    if (err)
      return err;
  }
  return 0;
}

} // namespace bpftrace
