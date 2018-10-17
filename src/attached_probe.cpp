#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <regex>
#include <sys/utsname.h>
#include <tuple>
#include <unistd.h>

#include "attached_probe.h"
#include "bpftrace.h"
#include "bcc_syms.h"
#include "bcc_usdt.h"
#include "common.h"
#include "libbpf.h"
#include "utils-inl.h"
#include <linux/perf_event.h>
#include <linux/version.h>

namespace bpftrace {

const int BPF_LOG_SIZE = 100 * 1024;

bpf_probe_attach_type attachtype(ProbeType t)
{
  switch (t)
  {
    case ProbeType::kprobe:    return BPF_PROBE_ENTRY;  break;
    case ProbeType::kretprobe: return BPF_PROBE_RETURN; break;
    case ProbeType::uprobe:    return BPF_PROBE_ENTRY;  break;
    case ProbeType::uretprobe: return BPF_PROBE_RETURN; break;
    case ProbeType::usdt:      return BPF_PROBE_ENTRY; break;
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
    case ProbeType::usdt:       return BPF_PROG_TYPE_KPROBE; break;
    case ProbeType::tracepoint: return BPF_PROG_TYPE_TRACEPOINT; break;
    case ProbeType::profile:      return BPF_PROG_TYPE_PERF_EVENT; break;
    case ProbeType::interval:      return BPF_PROG_TYPE_PERF_EVENT; break;
    case ProbeType::software:   return BPF_PROG_TYPE_PERF_EVENT; break;
    case ProbeType::hardware:   return BPF_PROG_TYPE_PERF_EVENT; break;
    default: abort();
  }
}


AttachedProbe::AttachedProbe(Probe &probe, std::tuple<uint8_t *, uintptr_t> func)
  : probe_(probe), func_(func)
{
  load_prog();
  if (bt_verbose)
    std::cerr << "Attaching " << probe_.name << std::endl;
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
    case ProbeType::interval:
      attach_interval();
      break;
    case ProbeType::software:
      attach_software();
      break;
    case ProbeType::hardware:
      attach_hardware();
      break;
    default:
      abort();
  }
}

AttachedProbe::AttachedProbe(Probe &probe, std::tuple<uint8_t *, uintptr_t> func, int pid)
  : probe_(probe), func_(func)
{
  load_prog();
  switch (probe_.type)
  {
    case ProbeType::usdt:
      attach_usdt(pid);
      break;
    default:
      abort();
  }
}

AttachedProbe::~AttachedProbe()
{
  if (progfd_ >= 0)
    close(progfd_);

  int err = 0;
  for (int perf_event_fd : perf_event_fds_)
  {
    err = bpf_close_perf_event_fd(perf_event_fd);
    if (err)
      std::cerr << "Error closing perf event FDs for probe: " << probe_.name << std::endl;
  }

  err = 0;
  switch (probe_.type)
  {
    case ProbeType::kprobe:
    case ProbeType::kretprobe:
      err = bpf_detach_kprobe(eventname().c_str());
      break;
    case ProbeType::uprobe:
    case ProbeType::uretprobe:
    case ProbeType::usdt:
      err = bpf_detach_uprobe(eventname().c_str());
      break;
    case ProbeType::tracepoint:
      err = bpf_detach_tracepoint(probe_.path.c_str(), eventname().c_str());
      break;
    case ProbeType::profile:
    case ProbeType::interval:
    case ProbeType::software:
    case ProbeType::hardware:
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
  std::string index_str = "_" + std::to_string(probe_.index);
  switch (probe_.type)
  {
    case ProbeType::kprobe:
    case ProbeType::kretprobe:
      return eventprefix() + probe_.attach_point + index_str;
    case ProbeType::uprobe:
    case ProbeType::uretprobe:
    case ProbeType::usdt:
      offset_str << std::hex << offset();
      return eventprefix() + sanitise(probe_.path) + "_" + offset_str.str() + index_str;
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
      probe_.loc, 0, nullptr, &sym);

  if (err)
    throw std::runtime_error("Could not resolve symbol: " + probe_.path + ":" + probe_.attach_point);

  return sym.offset;
}

static unsigned kernel_version(int attempt)
{
  switch (attempt)
  {
    case 0:
      return LINUX_VERSION_CODE;
    case 1:
      struct utsname utsname;
      if (uname(&utsname) < 0)
        return 0;
      unsigned x, y, z;
      if (sscanf(utsname.release, "%u.%u.%u", &x, &y, &z) != 3)
        return 0;
      return KERNEL_VERSION(x, y, z);
    case 2:
      // try to get the definition of LINUX_VERSION_CODE at runtime.
      // needed if bpftrace is compiled on a different linux version than it's used on.
      // e.g. if built with docker.
      // the reason case 0 doesn't work for this is because it uses the preprocessor directive,
      // which is by definition a compile-time constant
      std::ifstream linux_version_header{"/usr/include/linux/version.h"};
      const std::string content{std::istreambuf_iterator<char>(linux_version_header),
                                std::istreambuf_iterator<char>()};
      const std::regex regex{"#define\\s+LINUX_VERSION_CODE\\s+(\\d+)"};
      std::smatch match;

      if (std::regex_search(content.begin(), content.end(), match, regex))
        return static_cast<unsigned>(std::stoi(match[1]));

      return 0;
  }
  abort();
}

void AttachedProbe::load_prog()
{
  uint8_t *insns = std::get<0>(func_);
  int prog_len = std::get<1>(func_);
  const char *license = "GPL";
  int log_level = 0;
  char log_buf[BPF_LOG_SIZE];
  char name[STRING_SIZE], *namep;
  unsigned log_buf_size = sizeof (log_buf);

  // Redirect stderr, so we don't get error messages from BCC
  int old_stderr, new_stderr;
  fflush(stderr);
  if (bt_debug != DebugLevel::kNone)
    log_level = 15;
  else
  {
    old_stderr = dup(2);
    new_stderr = open("/dev/null", O_WRONLY);
    dup2(new_stderr, 2);
    close(new_stderr);
  }

   if (bt_verbose)
    log_level = 1;

  // bpf_prog_load rejects colons in the probe name
  strncpy(name, probe_.name.c_str(), STRING_SIZE);
  namep = name;
  if (strrchr(name, ':') != NULL)
    namep = strrchr(name, ':') + 1;

  for (int attempt=0; attempt<3; attempt++)
  {
    progfd_ = bpf_prog_load(progtype(probe_.type), namep,
        reinterpret_cast<struct bpf_insn*>(insns), prog_len, license,
        kernel_version(attempt), log_level, log_buf, log_buf_size);
    if (progfd_ >= 0)
      break;
  }

  // Restore stderr
  if (bt_debug == DebugLevel::kNone)
  {
    fflush(stderr);
    dup2(old_stderr, 2);
    close(old_stderr);
  }

  if (progfd_ < 0) {
    if (bt_verbose)
      std::cerr << std::endl << "Error log: " << std::endl << log_buf << std::endl;
    throw std::runtime_error("Error loading program: " + probe_.name + (bt_verbose ? "" : " (try -v)"));
  } else {
    if (bt_verbose) {
       std::cout << std::endl << "Bytecode: " << std::endl << log_buf << std::endl;
    }
  }
}

void AttachedProbe::attach_kprobe()
{
  int perf_event_fd = bpf_attach_kprobe(progfd_, attachtype(probe_.type),
      eventname().c_str(), probe_.attach_point.c_str(), 0);

  if (perf_event_fd < 0) {
    if (probe_.orig_name != probe_.name) {
      // a wildcard expansion couldn't probe something, just print a warning
      // as this is normal for some kernel functions (eg, do_debug())
      std::cerr << "Warning: could not attach probe " << probe_.name << ", skipping." << std::endl;
    } else {
      // an explicit match failed, so fail as the user must have wanted it
      throw std::runtime_error("Error attaching probe: '" + probe_.name + "'");
    }
  }

  perf_event_fds_.push_back(perf_event_fd);
}

void AttachedProbe::attach_uprobe()
{
  int pid = -1;

  int perf_event_fd = bpf_attach_uprobe(progfd_, attachtype(probe_.type),
      eventname().c_str(), probe_.path.c_str(), offset(), pid);

  if (perf_event_fd < 0)
    throw std::runtime_error("Error attaching probe: " + probe_.name);

  perf_event_fds_.push_back(perf_event_fd);
}

void AttachedProbe::attach_usdt(int pid)
{
  struct bcc_usdt_location loc = {};
  int err;
  void *ctx;

  if (pid)
  {
    ctx = bcc_usdt_new_frompid(pid, probe_.path.c_str());
    if (!ctx)
      throw std::runtime_error("Error initializing context for probe: " + probe_.name + ", for PID: " + std::to_string(pid));
  }
  else
  {
    ctx = bcc_usdt_new_frompath(probe_.path.c_str());
    if (!ctx)
      throw std::runtime_error("Error initializing context for probe: " + probe_.name);
  }

  // TODO: fn_name may need a unique suffix for each attachment on the same probe:
  std::string fn_name = "probe_" + probe_.attach_point + "_1";
  err = bcc_usdt_enable_probe(ctx, probe_.attach_point.c_str(), fn_name.c_str());
  if (err)
    throw std::runtime_error("Error finding or enabling probe: " + probe_.name);

  std::string provider_name = GetProviderFromPath(probe_.path);

  err = bcc_usdt_get_location(ctx, provider_name.c_str(), probe_.attach_point.c_str(), 0, &loc);
  if (err)
    throw std::runtime_error("Error finding location for probe: " + probe_.name);
  probe_.loc = loc.address;

  int perf_event_fd = bpf_attach_uprobe(progfd_, attachtype(probe_.type),
      eventname().c_str(), probe_.path.c_str(), offset(), pid == 0 ? -1 : pid);

  if (perf_event_fd < 0)
  {
    if (pid)
      throw std::runtime_error("Error attaching probe: " + probe_.name + ", to PID: " + std::to_string(pid));
    else
      throw std::runtime_error("Error attaching probe: " + probe_.name);
  }

  perf_event_fds_.push_back(perf_event_fd);
}

void AttachedProbe::attach_tracepoint()
{
  int perf_event_fd = bpf_attach_tracepoint(progfd_, probe_.path.c_str(),
      eventname().c_str());

  if (perf_event_fd < 0)
    throw std::runtime_error("Error attaching probe: " + probe_.name);

  perf_event_fds_.push_back(perf_event_fd);
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

void AttachedProbe::attach_interval()
{
  int pid = -1;
  int group_fd = -1;
  int cpu = 0;

  uint64_t period, freq;
  if (probe_.path == "s")
  {
    period = probe_.freq * 1e9;
    freq = 0;
  }
  else if (probe_.path == "ms")
  {
    period = probe_.freq * 1e6;
    freq = 0;
  }
  else
  {
    abort();
  }

  int perf_event_fd = bpf_attach_perf_event(progfd_, PERF_TYPE_SOFTWARE,
      PERF_COUNT_SW_CPU_CLOCK, period, freq, pid, cpu, group_fd);

  if (perf_event_fd < 0)
    throw std::runtime_error("Error attaching probe: " + probe_.name);

  perf_event_fds_.push_back(perf_event_fd);
}

void AttachedProbe::attach_software()
{
  int pid = -1;
  int group_fd = -1;

  uint64_t period = probe_.freq;
  uint64_t defaultp = 1;
  uint32_t type;

  // from linux/perf_event.h, with aliases from perf:
  if (probe_.path == "cpu-clock" || probe_.path == "cpu")
  {
    type = PERF_COUNT_SW_CPU_CLOCK;
    defaultp = 1000000;
  }
  else if (probe_.path == "task-clock")
  {
    type = PERF_COUNT_SW_TASK_CLOCK;
  }
  else if (probe_.path == "page-faults" || probe_.path == "faults")
  {
    type = PERF_COUNT_SW_PAGE_FAULTS;
    defaultp = 100;
  }
  else if (probe_.path == "context-switches" || probe_.path == "cs")
  {
    type = PERF_COUNT_SW_CONTEXT_SWITCHES;
    defaultp = 1000;
  }
  else if (probe_.path == "cpu-migrations")
  {
    type = PERF_COUNT_SW_CPU_MIGRATIONS;
  }
  else if (probe_.path == "minor-faults")
  {
    type = PERF_COUNT_SW_PAGE_FAULTS_MIN;
    defaultp = 100;
  }
  else if (probe_.path == "major-faults")
  {
    type = PERF_COUNT_SW_PAGE_FAULTS_MAJ;
  }
  else if (probe_.path == "alignment-faults")
  {
    type = PERF_COUNT_SW_ALIGNMENT_FAULTS;
  }
  else if (probe_.path == "emulation-faults")
  {
    type = PERF_COUNT_SW_EMULATION_FAULTS;
  }
  else if (probe_.path == "dummy")
  {
    type = PERF_COUNT_SW_DUMMY;
  }
  else if (probe_.path == "bpf-output")
  {
    type = PERF_COUNT_SW_BPF_OUTPUT;
  }
  else
  {
    abort();
  }

  if (period == 0)
    period = defaultp;

  std::vector<int> cpus = ebpf::get_online_cpus();
  for (int cpu : cpus)
  {
    int perf_event_fd = bpf_attach_perf_event(progfd_, PERF_TYPE_SOFTWARE,
        type, period, 0, pid, cpu, group_fd);

    if (perf_event_fd < 0)
      throw std::runtime_error("Error attaching probe: " + probe_.name);

    perf_event_fds_.push_back(perf_event_fd);
  }
}

void AttachedProbe::attach_hardware()
{
  int pid = -1;
  int group_fd = -1;

  uint64_t period = probe_.freq;
  uint64_t defaultp = 1000000;
  uint32_t type;

  // from linux/perf_event.h, with aliases from perf:
  if (probe_.path == "cpu-cycles" || probe_.path == "cycles")
  {
    type = PERF_COUNT_HW_CPU_CYCLES;
  }
  else if (probe_.path == "instructions")
  {
    type = PERF_COUNT_HW_INSTRUCTIONS;
  }
  else if (probe_.path == "cache-references")
  {
    type = PERF_COUNT_HW_CACHE_REFERENCES;
  }
  else if (probe_.path == "cache-misses")
  {
    type = PERF_COUNT_HW_CACHE_MISSES;
  }
  else if (probe_.path == "branch-instructions" || probe_.path == "branches")
  {
    type = PERF_COUNT_HW_BRANCH_INSTRUCTIONS;
    defaultp = 100000;
  }
  else if (probe_.path == "bus-cycles")
  {
    type = PERF_COUNT_HW_BUS_CYCLES;
    defaultp = 100000;
  }
  else if (probe_.path == "frontend-stalls")
  {
    type = PERF_COUNT_HW_STALLED_CYCLES_FRONTEND;
  }
  else if (probe_.path == "backend-stalls")
  {
    type = PERF_COUNT_HW_STALLED_CYCLES_BACKEND;
  }
  else if (probe_.path == "ref-cycles")
  {
    type = PERF_COUNT_HW_REF_CPU_CYCLES;
  }
  // can add PERF_COUNT_HW_CACHE_... here
  else
  {
    abort();
  }

  if (period == 0)
    period = defaultp;

  std::vector<int> cpus = ebpf::get_online_cpus();
  for (int cpu : cpus)
  {
    int perf_event_fd = bpf_attach_perf_event(progfd_, PERF_TYPE_HARDWARE,
        type, period, 0, pid, cpu, group_fd);

    if (perf_event_fd < 0)
      throw std::runtime_error("Error attaching probe: " + probe_.name);

    perf_event_fds_.push_back(perf_event_fd);
  }
}

} // namespace bpftrace
