#include <iostream>
#include <tuple>
#include <sys/utsname.h>
#include <unistd.h>

#include "attached_probe.h"
#include "bcc_syms.h"
#include "libbpf.h"
#include "perf_reader.h"

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
    case ProbeType::kprobe:    return BPF_PROG_TYPE_KPROBE; break;
    case ProbeType::kretprobe: return BPF_PROG_TYPE_KPROBE; break;
    case ProbeType::uprobe:    return BPF_PROG_TYPE_KPROBE; break;
    case ProbeType::uretprobe: return BPF_PROG_TYPE_KPROBE; break;
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
    default:
      abort();
  }
}

AttachedProbe::~AttachedProbe()
{
  close(progfd_);
  perf_reader_free(perf_reader_);
  int err = 0;
  switch (probe_.type)
  {
    case ProbeType::kprobe:
    case ProbeType::kretprobe:
      err = bpf_detach_kprobe(eventname());
      break;
    case ProbeType::uprobe:
    case ProbeType::uretprobe:
      err = bpf_detach_uprobe(eventname());
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

const char *AttachedProbe::eventname() const
{
  std::string event;
  std::ostringstream offset_str;
  switch (probe_.type)
  {
    case ProbeType::kprobe:
    case ProbeType::kretprobe:
      event = eventprefix() + probe_.attach_point;
      break;
    case ProbeType::uprobe:
    case ProbeType::uretprobe:
      offset_str << std::hex << offset();
      event = eventprefix() + probe_.path + "_" + offset_str.str();
      break;
    default:
      abort();
  }
  return event.c_str();
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
  char *log_buf = nullptr;
  unsigned log_buf_size = 0;

  progfd_ = bpf_prog_load(progtype(probe_.type),
      reinterpret_cast<struct bpf_insn*>(insns), prog_len,
      license, kern_version, log_buf, log_buf_size);

  if (progfd_ < 0)
    throw std::runtime_error("Error loading program: " + probe_.name);
}

void AttachedProbe::attach_kprobe()
{
  int pid = -1;
  int cpu = 0;
  int group_fd = -1;
  perf_reader_cb cb = nullptr;
  void *cb_cookie = nullptr;

  perf_reader_ = bpf_attach_kprobe(progfd_, attachtype(probe_.type),
      eventname(), probe_.attach_point.c_str(),
      pid, cpu, group_fd, cb, cb_cookie);

  if (perf_reader_ == nullptr)
    throw std::runtime_error("Error attaching probe: " + probe_.name);
}

void AttachedProbe::attach_uprobe()
{
  int pid = -1;
  int cpu = 0;
  int group_fd = -1;
  perf_reader_cb cb = nullptr;
  void *cb_cookie = nullptr;

  perf_reader_ = bpf_attach_uprobe(progfd_, attachtype(probe_.type),
      eventname(), probe_.path.c_str(), offset(),
      pid, cpu, group_fd, cb, cb_cookie);

  if (perf_reader_ == nullptr)
    throw std::runtime_error("Error attaching probe: " + probe_.name);
}

} // namespace bpftrace
