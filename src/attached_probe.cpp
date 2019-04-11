#include <cstring>
#include <elf.h>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <link.h>
#include <regex>
#include <sys/auxv.h>
#include <sys/utsname.h>
#include <tuple>
#include <unistd.h>

#include "attached_probe.h"
#include "bpftrace.h"
#include "utils.h"
#include "bcc_syms.h"
#include "bcc_usdt.h"
#include "libbpf.h"
#include "utils.h"
#include "list.h"
#include <linux/perf_event.h>
#include <linux/version.h>

namespace bpftrace {

const int BPF_LOG_SIZE = 100 * 1024;
/*
 * Kernel functions that are unsafe to trace are excluded in the Kernel with
 * `notrace`. However, the ones below are not excluded.
 */
const std::set<std::string> banned_kretprobes = {
  "_raw_spin_lock", "_raw_spin_lock_irqsave", "_raw_spin_unlock_irqrestore",
  "queued_spin_lock_slowpath",
};


bpf_probe_attach_type attachtype(ProbeType t)
{
  switch (t)
  {
    case ProbeType::kprobe:    return BPF_PROBE_ENTRY;  break;
    case ProbeType::kretprobe: return BPF_PROBE_RETURN; break;
    case ProbeType::uprobe:    return BPF_PROBE_ENTRY;  break;
    case ProbeType::uretprobe: return BPF_PROBE_RETURN; break;
    case ProbeType::usdt:      return BPF_PROBE_ENTRY;  break;
    default:
      std::cerr << "invalid probe attachtype \"" << probetypeName(t) << "\"" << std::endl;
      abort();
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
    default:
      std::cerr << "program type not found" << std::endl;
      abort();
  }
}

void check_banned_kretprobes(std::string const& kprobe_name) {
  if (banned_kretprobes.find(kprobe_name) != banned_kretprobes.end()) {
    std::cerr << "error: kretprobe:" << kprobe_name << " can't be used as it might lock up your system." << std::endl;
    exit(1);
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
      attach_kprobe();
      break;
    case ProbeType::kretprobe:
      check_banned_kretprobes(probe_.attach_point);
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
      std::cerr << "invalid attached probe type \"" << probetypeName(probe_.type) << "\"" << std::endl;
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
      std::cerr << "invalid attached probe type \"" << probetypeName(probe_.type) << "\"" << std::endl;
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
      std::cerr << "invalid attached probe type \"" << probetypeName(probe_.type) << "\" at destructor" << std::endl;
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
      std::cerr << "invalid eventprefix" << std::endl;
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
      return eventprefix() + sanitise(probe_.attach_point) + index_str;
    case ProbeType::uprobe:
    case ProbeType::uretprobe:
    case ProbeType::usdt:
      offset_str << std::hex << offset();
      return eventprefix() + sanitise(probe_.path) + "_" + offset_str.str() + index_str;
    case ProbeType::tracepoint:
      return probe_.attach_point;
    default:
      std::cerr << "invalid eventname probe \"" << probetypeName(probe_.type) << "\"" << std::endl;
      abort();
  }
}

std::string AttachedProbe::sanitise(const std::string &str)
{
  /*
   * Characters such as "." in event names are rejected by the kernel,
   * so sanitize:
   */
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

/**
 * Search for LINUX_VERSION_CODE in the vDSO, returning 0 if it can't be found.
 */
static unsigned _find_version_note(unsigned long base)
{
  auto ehdr = reinterpret_cast<const ElfW(Ehdr) *>(base);

  for (int i = 0; i < ehdr->e_shnum; i++)
  {
    auto shdr = reinterpret_cast<const ElfW(Shdr) *>(
      base + ehdr->e_shoff + (i * ehdr->e_shentsize)
    );

    if (shdr->sh_type == SHT_NOTE)
    {
      auto ptr = reinterpret_cast<const char *>(base + shdr->sh_offset);
      auto end = ptr + shdr->sh_size;

      while (ptr < end)
      {
        auto nhdr = reinterpret_cast<const ElfW(Nhdr) *>(ptr);
        ptr += sizeof *nhdr;

        auto name = ptr;
        ptr += (nhdr->n_namesz + sizeof(ElfW(Word)) - 1) & -sizeof(ElfW(Word));

        auto desc = ptr;
        ptr += (nhdr->n_descsz + sizeof(ElfW(Word)) - 1) & -sizeof(ElfW(Word));

        if ((nhdr->n_namesz > 5 && !memcmp(name, "Linux", 5)) &&
            nhdr->n_descsz == 4 && !nhdr->n_type)
          return *reinterpret_cast<const uint32_t *>(desc);
      }
    }
  }

  return 0;
}

/**
 * Find a LINUX_VERSION_CODE matching the host kernel. The build-time constant
 * may not match if bpftrace is compiled on a different Linux version than it's
 * used on, e.g. if built with Docker.
 */
static unsigned kernel_version(int attempt)
{
  switch (attempt)
  {
    case 0:
    {
      // Fetch LINUX_VERSION_CODE from the vDSO .note section, falling back on
      // the build-time constant if unavailable. This always matches the
      // running kernel, but is not supported on arm32.
      unsigned code = 0;
      unsigned long base = getauxval(AT_SYSINFO_EHDR);
      if (base && !memcmp(reinterpret_cast<void *>(base), ELFMAG, 4))
        code = _find_version_note(base);
      if (! code)
        code = LINUX_VERSION_CODE;
      return code;
    }
    case 1:
      struct utsname utsname;
      if (uname(&utsname) < 0)
        return 0;
      unsigned x, y, z;
      if (sscanf(utsname.release, "%u.%u.%u", &x, &y, &z) != 3)
        return 0;
      return KERNEL_VERSION(x, y, z);
    case 2:
    {
      // Try to get the definition of LINUX_VERSION_CODE at runtime.
      std::ifstream linux_version_header{"/usr/include/linux/version.h"};
      const std::string content{std::istreambuf_iterator<char>(linux_version_header),
                                std::istreambuf_iterator<char>()};
      const std::regex regex{"#define\\s+LINUX_VERSION_CODE\\s+(\\d+)"};
      std::smatch match;

      if (std::regex_search(content.begin(), content.end(), match, regex))
        return static_cast<unsigned>(std::stoi(match[1]));

      return 0;
    }
    default:
      break;
  }
  std::cerr << "invalid kernel version" << std::endl;
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
  int old_stderr = -1, new_stderr;
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
  strncpy(name, probe_.name.c_str(), STRING_SIZE - 1);
  namep = name;
  if (strrchr(name, ':') != NULL)
    namep = strrchr(name, ':') + 1;

  for (int attempt=0; attempt<3; attempt++)
  {
    auto version = kernel_version(attempt);
    if (version == 0 && attempt > 0) {
      // Recent kernels don't check the version so we should try to call
      // bcc_prog_load during first iteration even if we failed to determine the
      // version. We should not do that in subsequent iterations to avoid
      // zeroing of log_buf on systems with older kernels.
      continue;
    }

#ifdef HAVE_BCC_PROG_LOAD
    progfd_ = bcc_prog_load(progtype(probe_.type), namep,
#else
    progfd_ = bpf_prog_load(progtype(probe_.type), namep,
#endif
        reinterpret_cast<struct bpf_insn*>(insns), prog_len, license,
        version, log_level, log_buf, log_buf_size);
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
  }

  if (bt_verbose) {
    struct bpf_prog_info info = {};
    uint32_t info_len = sizeof(info);
    int ret;

    ret = bpf_obj_get_info(progfd_, &info, &info_len);
    if (ret == 0) {
      std::cout << std::endl << "Program ID: " << info.id << std::endl;
    }
    std::cout << std::endl << "Bytecode: " << std::endl << log_buf << std::endl;
  }
}

// XXX(mmarchini): bcc changed the signature of bpf_attach_kprobe, adding a new
// int parameter at the end. Since there's no reliable way to feature-detect
// this, we create a function pointer with the long signature and cast
// bpf_attach_kprobe to this function pointer. If we're on an older bcc
// version, bpf_attach_kprobe call will be augmented with an extra register
// being used for the last parameter, even though this register won't be used
// inside the function. Since the register won't be used this is kinda safe,
// although not ideal.
typedef int (*attach_probe_wrapper_signature)(int, enum bpf_probe_attach_type, const char*, const char*, uint64_t, int);

void AttachedProbe::attach_kprobe()
{
  int perf_event_fd = reinterpret_cast<attach_probe_wrapper_signature>(&bpf_attach_kprobe)(progfd_, attachtype(probe_.type),
      eventname().c_str(), probe_.attach_point.c_str(), 0, 0);

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
  std::string provider_ns;
  void *ctx;

  if (pid)
  {
    //FIXME when iovisor/bcc#2604 is merged, optionally pass probe_.path
    ctx = bcc_usdt_new_frompid(pid, nullptr);
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

  auto u = USDTHelper::find(ctx, pid, probe_.attach_point);
  probe_.path = std::get<1>(u);
  // Handle manually specifying probe provider namespace
  if (probe_.ns != "")
    provider_ns = probe_.ns;
  else
    provider_ns = std::get<0>(u);

  err = bcc_usdt_get_location(ctx, provider_ns.c_str(), probe_.attach_point.c_str(), 0, &loc);
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
    std::cerr << "invalid profile path \"" << probe_.path << "\"" << std::endl;
    abort();
  }

  std::vector<int> cpus = get_online_cpus();
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
    std::cerr << "invalid interval path \"" << probe_.path << "\"" << std::endl;
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
  uint32_t type = 0;

  // from linux/perf_event.h, with aliases from perf:
  for (auto &probeListItem : SW_PROBE_LIST)
  {
    if (probe_.path == probeListItem.path || probe_.path == probeListItem.alias)
    {
      type = probeListItem.type;
      defaultp = probeListItem.defaultp;
    }
  }

  if (period == 0)
    period = defaultp;

  std::vector<int> cpus = get_online_cpus();
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
  uint32_t type = 0;

  // from linux/perf_event.h, with aliases from perf:
  for (auto &probeListItem : HW_PROBE_LIST)
  {
    if (probe_.path == probeListItem.path || probe_.path == probeListItem.alias)
    {
      type = probeListItem.type;
      defaultp = probeListItem.defaultp;
    }
  }

  if (period == 0)
    period = defaultp;

  std::vector<int> cpus = get_online_cpus();
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
