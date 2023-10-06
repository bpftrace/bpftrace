#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <algorithm>
#include <cstring>
#include <elf.h>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <linux/hw_breakpoint.h>
#include <linux/limits.h>
#include <linux/perf_event.h>
#include <regex>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <tuple>
#include <unistd.h>

#include <bcc/bcc_elf.h>
#include <bcc/bcc_syms.h>
#include <bcc/bcc_usdt.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "attached_probe.h"
#include "bpftrace.h"
#include "disasm.h"
#include "log.h"
#include "probe_matcher.h"
#include "usdt.h"

namespace bpftrace {

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
  // clang-format off
  switch (t)
  {
    case ProbeType::kprobe:    return BPF_PROBE_ENTRY;  break;
    case ProbeType::kretprobe: return BPF_PROBE_RETURN; break;
    case ProbeType::special:   return BPF_PROBE_ENTRY;  break;
    case ProbeType::uprobe:    return BPF_PROBE_ENTRY;  break;
    case ProbeType::uretprobe: return BPF_PROBE_RETURN; break;
    case ProbeType::usdt:      return BPF_PROBE_ENTRY;  break;
    default:
      LOG(FATAL) << "invalid probe attachtype \"" << probetypeName(t) << "\"";
  }
  // clang-format on
  // lgtm[cpp/missing-return]
}

libbpf::bpf_prog_type progtype(ProbeType t)
{
  switch (t)
  {
    // clang-format off
    case ProbeType::special:    return libbpf::BPF_PROG_TYPE_RAW_TRACEPOINT; break;
    case ProbeType::kprobe:     return libbpf::BPF_PROG_TYPE_KPROBE; break;
    case ProbeType::kretprobe:  return libbpf::BPF_PROG_TYPE_KPROBE; break;
    case ProbeType::uprobe:     return libbpf::BPF_PROG_TYPE_KPROBE; break;
    case ProbeType::uretprobe:  return libbpf::BPF_PROG_TYPE_KPROBE; break;
    case ProbeType::usdt:       return libbpf::BPF_PROG_TYPE_KPROBE; break;
    case ProbeType::tracepoint: return libbpf::BPF_PROG_TYPE_TRACEPOINT; break;
    case ProbeType::profile:    return libbpf::BPF_PROG_TYPE_PERF_EVENT; break;
    case ProbeType::interval:   return libbpf::BPF_PROG_TYPE_PERF_EVENT; break;
    case ProbeType::software:   return libbpf::BPF_PROG_TYPE_PERF_EVENT; break;
    case ProbeType::watchpoint: return libbpf::BPF_PROG_TYPE_PERF_EVENT; break;
    case ProbeType::asyncwatchpoint: return libbpf::BPF_PROG_TYPE_PERF_EVENT; break;
    case ProbeType::hardware:   return libbpf::BPF_PROG_TYPE_PERF_EVENT; break;
    case ProbeType::kfunc:      return libbpf::BPF_PROG_TYPE_TRACING; break;
    case ProbeType::kretfunc:   return libbpf::BPF_PROG_TYPE_TRACING; break;
    case ProbeType::iter:       return libbpf::BPF_PROG_TYPE_TRACING; break;
    case ProbeType::rawtracepoint: return libbpf::BPF_PROG_TYPE_RAW_TRACEPOINT; break;
    // clang-format on
    case ProbeType::invalid:
      LOG(FATAL) << "program type invalid";
  }

  return {}; // unreached
}

std::string progtypeName(libbpf::bpf_prog_type t)
{
  switch (t)
  {
    // clang-format off
    case libbpf::BPF_PROG_TYPE_KPROBE:     return "BPF_PROG_TYPE_KPROBE";     break;
    case libbpf::BPF_PROG_TYPE_TRACEPOINT: return "BPF_PROG_TYPE_TRACEPOINT"; break;
    case libbpf::BPF_PROG_TYPE_PERF_EVENT: return "BPF_PROG_TYPE_PERF_EVENT"; break;
    case libbpf::BPF_PROG_TYPE_TRACING:    return "BPF_PROG_TYPE_TRACING";    break;
    // clang-format on
    default:
      LOG(FATAL) << "invalid program type: " << t;
  }
  // lgtm[cpp/missing-return]
}

void check_banned_kretprobes(std::string const& kprobe_name) {
  if (banned_kretprobes.find(kprobe_name) != banned_kretprobes.end()) {
    LOG(ERROR) << "error: kretprobe:" << kprobe_name
               << " can't be used as it might lock up your system.";
    exit(1);
  }
}

void AttachedProbe::attach_kfunc(void)
{
  if (progfd_ < 0)
    // Errors for kfunc are handled in load_prog, ignore here
    return;
  tracing_fd_ = bpf_raw_tracepoint_open(nullptr, progfd_);
  if (tracing_fd_ < 0)
    throw std::runtime_error("Error attaching probe: " + probe_.name);
}

int AttachedProbe::detach_kfunc(void)
{
  close(tracing_fd_);
  return 0;
}

void AttachedProbe::attach_iter(void)
{
  linkfd_ = bpf_link_create(progfd_,
                            0,
                            static_cast<enum ::bpf_attach_type>(
                                libbpf::BPF_TRACE_ITER),
                            NULL);
  if (linkfd_ < 0)
  {
    throw std::runtime_error("Error attaching probe: '" + probe_.name + "'");
  }
}

int AttachedProbe::detach_iter(void)
{
  close(linkfd_);
  return 0;
}

void AttachedProbe::attach_raw_tracepoint(void)
{
  if (progfd_ < 0)
    // Errors for raw_tracepoint are handled in load_prog, ignore here
    return;
  tracing_fd_ = bpf_raw_tracepoint_open(probe_.attach_point.c_str(), progfd_);
  if (tracing_fd_ < 0)
  {
    if (tracing_fd_ == -ENOENT)
      throw std::runtime_error("Probe does not exist: " + probe_.name);
    else if (tracing_fd_ == -EINVAL)
      throw std::runtime_error("Error attaching probe: " + probe_.name +
                               ", maybe trying to access arguments beyond "
                               "what's available in this tracepoint");
    else
      throw std::runtime_error("Error attaching probe: " + probe_.name);
  }
}

int AttachedProbe::detach_raw_tracepoint(void)
{
  close(tracing_fd_);
  return 0;
}

AttachedProbe::AttachedProbe(Probe &probe,
                             BpfProgram &&prog,
                             bool safe_mode,
                             BPFfeature &feature,
                             BTF &btf)
    : probe_(probe), prog_(std::move(prog)), btf_(btf)
{
  load_prog(feature);
  if (bt_verbose)
    std::cerr << "Attaching " << probe_.orig_name << std::endl;
  switch (probe_.type)
  {
    case ProbeType::special:
      // If BPF_PROG_TYPE_RAW_TRACEPOINT is available, no need to attach prog
      // to anything -- we will simply BPF_PROG_RUN it
      if (!feature.has_raw_tp_special())
        attach_uprobe(safe_mode);
      break;
    case ProbeType::kprobe:
      attach_kprobe(safe_mode);
      break;
    case ProbeType::kretprobe:
      check_banned_kretprobes(probe_.attach_point);
      attach_kprobe(safe_mode);
      break;
    case ProbeType::uprobe:
    case ProbeType::uretprobe:
      attach_uprobe(safe_mode);
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
    case ProbeType::kfunc:
    case ProbeType::kretfunc:
      attach_kfunc();
      break;
    case ProbeType::iter:
      attach_iter();
      break;
    case ProbeType::rawtracepoint:
      attach_raw_tracepoint();
      break;
    default:
      LOG(FATAL) << "invalid attached probe type \""
                 << probetypeName(probe_.type) << "\"";
  }
}

AttachedProbe::AttachedProbe(Probe &probe,
                             BpfProgram &&prog,
                             int pid,
                             BPFfeature &feature,
                             BTF &btf)
    : probe_(probe), prog_(std::move(prog)), btf_(btf)
{
  load_prog(feature);
  switch (probe_.type)
  {
    case ProbeType::usdt:
      attach_usdt(pid, feature);
      break;
    case ProbeType::watchpoint:
    case ProbeType::asyncwatchpoint:
      attach_watchpoint(pid, probe.mode);
      break;
    default:
      LOG(FATAL) << "invalid attached probe type \""
                 << probetypeName(probe_.type) << "\"";
  }
}

AttachedProbe::~AttachedProbe()
{
  int err = 0;
  for (int perf_event_fd : perf_event_fds_)
  {
    err = bpf_close_perf_event_fd(perf_event_fd);
    if (err)
      LOG(ERROR) << "failed to close perf event FDs for probe: " << probe_.name;
  }

  err = 0;
  switch (probe_.type)
  {
    case ProbeType::kprobe:
    case ProbeType::kretprobe:
      if (probe_.funcs.empty())
        err = bpf_detach_kprobe(eventname().c_str());
      else
        close(linkfd_);
      break;
    case ProbeType::kfunc:
    case ProbeType::kretfunc:
      err = detach_kfunc();
      break;
    case ProbeType::iter:
      err = detach_iter();
      break;
    case ProbeType::uprobe:
    case ProbeType::uretprobe:
    case ProbeType::usdt:
      if (usdt_destructor_)
        usdt_destructor_();
      err = bpf_detach_uprobe(eventname().c_str());
      break;
    case ProbeType::tracepoint:
      err = bpf_detach_tracepoint(probe_.path.c_str(), eventname().c_str());
      break;
    case ProbeType::special:
    case ProbeType::profile:
    case ProbeType::interval:
    case ProbeType::software:
    case ProbeType::watchpoint:
    case ProbeType::asyncwatchpoint:
    case ProbeType::hardware:
      break;
    case ProbeType::rawtracepoint:
      err = detach_raw_tracepoint();
      break;
    case ProbeType::invalid:
      LOG(FATAL) << "invalid attached probe type \""
                 << probetypeName(probe_.type) << "\" at destructor";
  }
  if (btf_fd_ != -1)
    close(btf_fd_);

  if (err)
    LOG(ERROR) << "failed to detach probe: " << probe_.name;

  if (close_progfd_ && progfd_ >= 0)
    close(progfd_);
}

const Probe &AttachedProbe::probe() const
{
  return probe_;
}

int AttachedProbe::progfd() const
{
  return progfd_;
}

std::string AttachedProbe::eventprefix() const
{
  switch (attachtype(probe_.type))
  {
    case BPF_PROBE_ENTRY:
      return "p_";
    case BPF_PROBE_RETURN:
      return "r_";
  }

  return {}; // unreached
}

std::string AttachedProbe::eventname() const
{
  std::ostringstream offset_str;
  std::string index_str = "_" + std::to_string(probe_.index);
  switch (probe_.type)
  {
    case ProbeType::kprobe:
    case ProbeType::kretprobe:
    case ProbeType::rawtracepoint:
      offset_str << std::hex << offset_;
      return eventprefix() + sanitise_bpf_program_name(probe_.attach_point) +
             "_" + offset_str.str() + index_str;
    case ProbeType::special:
    case ProbeType::uprobe:
    case ProbeType::uretprobe:
    case ProbeType::usdt:
      offset_str << std::hex << offset_;
      return eventprefix() + sanitise_bpf_program_name(probe_.path) + "_" +
             offset_str.str() + index_str;
    case ProbeType::tracepoint:
      return probe_.attach_point;
    default:
      LOG(FATAL) << "invalid eventname probe \"" << probetypeName(probe_.type)
                 << "\"";
  }
}

static int sym_name_cb(const char *symname, uint64_t start,
                       uint64_t size, void *p)
{
  struct symbol *sym = static_cast<struct symbol*>(p);

  if (sym->name == symname)
  {
    sym->start = start;
    sym->size  = size;
    return -1;
  }

  return 0;
}

static int sym_address_cb(const char *symname, uint64_t start,
                          uint64_t size, void *p)
{
  struct symbol *sym = static_cast<struct symbol*>(p);

  if (sym->address >= start && sym->address < (start + size))
  {
    sym->start = start;
    sym->size  = size;
    sym->name  = symname;
    return -1;
  }

  return 0;
}

static uint64_t
resolve_offset(const std::string &path, const std::string &symbol, uint64_t loc)
{
  bcc_symbol bcc_sym;

  if (bcc_resolve_symname(path.c_str(), symbol.c_str(), loc, 0, nullptr, &bcc_sym))
     throw std::runtime_error("Could not resolve symbol: " + path + ":" + symbol);

  // Have to free sym.module, see:
  // https://github.com/iovisor/bcc/blob/ba73657cb8c4dab83dfb89eed4a8b3866255569a/src/cc/bcc_syms.h#L98-L99
  if (bcc_sym.module)
    ::free(const_cast<char *>(bcc_sym.module));

  return bcc_sym.offset;
}

static void check_alignment(std::string &path,
                            std::string &symbol,
                            uint64_t sym_offset,
                            uint64_t func_offset,
                            bool safe_mode,
                            ProbeType type)
{
  Disasm dasm(path);
  AlignState aligned = dasm.is_aligned(sym_offset, func_offset);
  std::string probe_name = probetypeName(type);

  std::string tmp = path + ":" + symbol + "+" + std::to_string(func_offset);

  // If we did not allow unaligned uprobes in the
  // compile time, force the safe mode now.
#ifndef HAVE_UNSAFE_PROBE
  safe_mode = true;
#endif

  switch (aligned)
  {
    case AlignState::Ok:
      return;
    case AlignState::NotAlign:
      if (safe_mode)
        throw std::runtime_error("Could not add " + probe_name +
                                 " into middle of instruction: " + tmp);
      else
        LOG(WARNING) << "Unsafe " + probe_name +
                            " in the middle of the instruction: "
                     << tmp;
      break;

    case AlignState::Fail:
      if (safe_mode)
        throw std::runtime_error("Failed to check if " + probe_name +
                                 " is in proper place: " + tmp);
      else
        LOG(WARNING) << "Unchecked " + probe_name + ": " << tmp;
      break;

    case AlignState::NotSupp:
      if (safe_mode)
        throw std::runtime_error("Can't check if " + probe_name +
                                 " is in proper place (compiled without "
                                 "(k|u)probe offset support): " +
                                 tmp);
      else
        LOG(WARNING) << "Unchecked " + probe_name + " : " << tmp;
      break;
  }
}

bool AttachedProbe::resolve_offset_uprobe(bool safe_mode)
{
  struct bcc_symbol_option option = { };
  struct symbol sym = { };
  std::string &symbol = probe_.attach_point;
  uint64_t func_offset = probe_.func_offset;

  sym.name = "";
  option.use_debug_file  = 1;
  option.use_symbol_type = 0xffffffff;

  if (symbol.empty())
  {
    sym.address = probe_.address;
    bcc_elf_foreach_sym(probe_.path.c_str(), sym_address_cb, &option, &sym);

    if (!sym.start)
    {
      if (safe_mode)
      {
        std::stringstream ss;
        ss << "0x" << std::hex << probe_.address;
        throw std::runtime_error("Could not resolve address: " + probe_.path +
                                 ":" + ss.str());
      }
      else
      {
        LOG(WARNING) << "Could not determine instruction boundary for "
                     << probe_.name
                     << " (binary appears stripped). Misaligned probes "
                        "can lead to tracee crashes!";
        offset_ = probe_.address;
        return true;
      }
    }

    symbol = sym.name;
    func_offset = probe_.address - sym.start;
  }
  else
  {
    sym.name = symbol;
    bcc_elf_foreach_sym(probe_.path.c_str(), sym_name_cb, &option, &sym);

    if (!sym.start)
      throw std::runtime_error("Could not resolve symbol: " + probe_.path + ":" + symbol);
  }

  if (probe_.type == ProbeType::uretprobe && func_offset != 0) {
    std::stringstream msg;
    msg << "uretprobes cannot be attached at function offset. "
        << "(address resolved to: " << symbol << "+" << func_offset << ")";
    throw std::runtime_error(msg.str());
  }

  if (sym.size == 0 && func_offset == 0)
  {
    if (safe_mode)
    {
      std::stringstream msg;
      msg << "Could not determine boundary for " << sym.name
          << " (symbol has size 0).";
      if (probe_.orig_name == probe_.name)
      {
        msg << " Use --unsafe to force attachment.";
        throw std::runtime_error(msg.str());
      }
      else
      {
        LOG(WARNING)
            << msg.str()
            << " Skipping attachment (use --unsafe to force attachement).";
      }
      return false;
    }
  }
  else if (func_offset >= sym.size)
  {
    std::stringstream ss;
    ss << sym.size;
    throw std::runtime_error("Offset outside the function bounds ('" + symbol +
                             "' size is " + ss.str() + ")");
  }

  uint64_t sym_offset = resolve_offset(probe_.path, probe_.attach_point, probe_.loc);
  offset_ = sym_offset + func_offset;

  // If we are not aligned to the start of the symbol,
  // check if we are on the instruction boundary.
  if (func_offset == 0)
    return true;

  check_alignment(
      probe_.path, symbol, sym_offset, func_offset, safe_mode, probe_.type);
  return true;
}

// find vmlinux file containing the given symbol information
static std::string find_vmlinux(const struct vmlinux_location *locs,
                                struct symbol &sym)
{
  struct bcc_symbol_option option = {};
  option.use_debug_file = 0;
  option.use_symbol_type = BCC_SYM_ALL_TYPES;
  struct utsname buf;

  uname(&buf);

  for (int i = 0; locs[i].path; i++)
  {
    if (locs[i].raw)
      continue; // This file is for BTF. skip
    char path[PATH_MAX + 1];
    snprintf(path, PATH_MAX, locs[i].path, buf.release);
    if (access(path, R_OK))
      continue;
    bcc_elf_foreach_sym(path, sym_name_cb, &option, &sym);
    if (sym.start)
    {
      if (bt_verbose)
        std::cout << "vmlinux: using " << path << std::endl;
      return path;
    }
  }

  return "";
}

void AttachedProbe::resolve_offset_kprobe(bool safe_mode)
{
  struct symbol sym = {};
  std::string &symbol = probe_.attach_point;
  uint64_t func_offset = probe_.func_offset;
  offset_ = func_offset;

#ifndef HAVE_UNSAFE_PROBE
  safe_mode = true;
#endif

  if (func_offset == 0)
    return;

  sym.name = symbol;
  const struct vmlinux_location *locs = vmlinux_locs;
  struct vmlinux_location locs_env[] = {
    { nullptr, false },
    { nullptr, false },
  };
  char *env_path = std::getenv("BPFTRACE_VMLINUX");
  if (env_path)
  {
    locs_env[0].path = env_path;
    locs = locs_env;
  }

  std::string path = find_vmlinux(locs, sym);
  if (path.empty())
  {
    if (bt_verbose)
    {
      LOG(WARNING) << "Could not resolve symbol " << symbol
                   << ". Skipping usermode offset checking.";
      LOG(WARNING) << "The kernel will verify the safety of the location but "
                      "will also allow the offset to be in a different symbol.";
    }

    return;
  }

  if (func_offset >= sym.size)
    throw std::runtime_error("Offset outside the function bounds ('" + symbol +
                             "' size is " + std::to_string(sym.size) + ")");

  uint64_t sym_offset = resolve_offset(path, probe_.attach_point, probe_.loc);

  check_alignment(
      path, symbol, sym_offset, func_offset, safe_mode, probe_.type);
}

std::map<std::string, int> AttachedProbe::cached_prog_fds_;

bool AttachedProbe::use_cached_progfd(void)
{
  // Enabled for so far only for kprobes/kretprobes
  if (probe_.type != ProbeType::kprobe && probe_.type != ProbeType::kretprobe)
    return false;

  // Only for a wildcard probe which does not need expansion,
  // because we can have multiple programs attached to a single probe
  if (!has_wildcard(probe_.orig_name) || probe_.need_expansion)
    return false;

  // Keep map of loaded programs based on their 'orig_name',
  // and make sure they are loaded just once and use cached
  // fd as probe's progfd_.
  // This way we prevent multiple copies of the same program
  // loaded for wildcard probe.
  auto search = cached_prog_fds_.find(probe_.orig_name);

  if (search != cached_prog_fds_.end())
  {
    progfd_ = search->second;
    close_progfd_ = false;
    return true;
  }

  return false;
}

void AttachedProbe::cache_progfd(void)
{
  if (probe_.type != ProbeType::kprobe && probe_.type != ProbeType::kretprobe)
    return;
  cached_prog_fds_[probe_.orig_name] = progfd_;
}

namespace {
const std::regex helper_verifier_error_re(
    "[0-9]+: \\([0-9]+\\) call ([a-z|A-Z|0-9|_]+)#([0-9]+)");
}

void AttachedProbe::load_prog(BPFfeature &feature)
{
  if (use_cached_progfd())
    return;

  auto &insns = prog_.getCode();
  const char *license = "GPL";
  int log_level = 0;

  uint64_t log_buf_size = probe_.log_size;
  auto log_buf = std::make_unique<char[]>(log_buf_size);
  std::string name;
  std::string tracing_type;

  {
    if (bt_debug != DebugLevel::kNone)
      log_level = 15;
    if (bt_verbose)
      log_level = 1;

    if (probe_.type == ProbeType::kprobe || probe_.type == ProbeType::kretprobe)
    {
      // Use orig_name for program name so we get proper name for
      // wildcard probes, replace wildcards with '.'
      name = probe_.orig_name;
      std::replace(name.begin(), name.end(), '*', '.');
    }
    else
      name = probe_.name;

    // bpf_prog_load rejects some characters in probe names, so we clean them
    // start the name after the probe type, after ':'
    if (auto last_colon = name.rfind(':'); last_colon != std::string::npos)
      name = name.substr(last_colon + 1);
    name = sanitise_bpf_program_name(name);

    auto prog_type = progtype(probe_.type);
    if (probe_.type == ProbeType::special && !feature.has_raw_tp_special())
      prog_type = progtype(ProbeType::uprobe);

    for (int attempt = 0; attempt < 3; attempt++)
    {
      auto version = kernel_version(attempt);
      if (version == 0 && attempt > 0)
      {
        // Recent kernels don't check the version so we should try to call
        // bpf_prog_load during first iteration even if we failed to determine
        // the version. We should not do that in subsequent iterations to avoid
        // zeroing of log_buf on systems with older kernels.
        continue;
      }

      LIBBPF_OPTS(bpf_prog_load_opts, opts);
      opts.log_buf = log_buf.get();
      opts.log_size = log_buf_size;
      opts.log_level = log_level;

      if (probe_.type == ProbeType::kfunc)
        opts.expected_attach_type = static_cast<::bpf_attach_type>(
            libbpf::BPF_TRACE_FENTRY);
      else if (probe_.type == ProbeType::kretfunc)
        opts.expected_attach_type = static_cast<::bpf_attach_type>(
            libbpf::BPF_TRACE_FEXIT);
      else if (probe_.type == ProbeType::iter)
        opts.expected_attach_type = static_cast<::bpf_attach_type>(
            libbpf::BPF_TRACE_ITER);

      if ((probe_.type == ProbeType::kprobe ||
           probe_.type == ProbeType::kretprobe) &&
          feature.has_kprobe_multi() && !probe_.funcs.empty())
        opts.expected_attach_type = static_cast<::bpf_attach_type>(
            libbpf::BPF_TRACE_KPROBE_MULTI);

      if ((probe_.type == ProbeType::uprobe ||
           probe_.type == ProbeType::uretprobe) &&
          feature.has_uprobe_multi() && !probe_.funcs.empty())
        opts.expected_attach_type = static_cast<::bpf_attach_type>(
            libbpf::BPF_TRACE_UPROBE_MULTI);

      if (probe_.type == ProbeType::kfunc ||
          probe_.type == ProbeType::kretfunc || probe_.type == ProbeType::iter)
      {
        std::string mod = probe_.path;
        std::string fun = probe_.attach_point;
        if (probe_.type == ProbeType::iter)
          fun = "bpf_iter_" + fun;
        auto btf_id = btf_.get_btf_id_fd(fun, mod);
        if (btf_id.first < 0)
        {
          std::string msg = "No BTF found for " + mod + ":" + fun;
          if (probe_.orig_name != probe_.name)
          {
            // one attachpoint in a multi-attachpoint (wildcard or list) probe
            // failed, print a warning but continue
            LOG(WARNING) << msg << ", skipping.";
            return;
          }
          else
            // explicit match failed, fail hard
            throw std::runtime_error(msg);
        }

        opts.attach_btf_id = btf_id.first;
        opts.attach_btf_obj_fd = btf_id.second;
      }
      else
      {
        opts.kern_version = version;
      }

      {
        // Redirect stderr, so we don't get error messages from libbpf
        StderrSilencer silencer;
        if (bt_debug == DebugLevel::kNone)
          silencer.silence();

        LIBBPF_OPTS(bpf_btf_load_opts,
                    btf_opts,
                    .log_buf = log_buf.get(),
                    .log_level = static_cast<__u32>(log_level),
                    .log_size = static_cast<__u32>(log_buf_size), );

        auto &btf = prog_.getBTF();
        btf_fd_ = bpf_btf_load(btf.data(), btf.size(), &btf_opts);

        opts.prog_btf_fd = btf_fd_;

        // Don't attempt to load the program if the BTF load failed.
        // This will fall back to the error handling for failed program load,
        // which is more robust.
        if (btf_fd_ >= 0)
          progfd_ = bpf_prog_load(static_cast<::bpf_prog_type>(prog_type),
                                  name.c_str(),
                                  license,
                                  reinterpret_cast<const struct bpf_insn *>(
                                      insns.data()),
                                  insns.size() / sizeof(struct bpf_insn),
                                  &opts);
      }

      if (opts.attach_prog_fd > 0)
        close(opts.attach_prog_fd);
      if (progfd_ >= 0)
        break;
    }
  }

  if (progfd_ < 0) {
    std::stringstream errmsg;
    if (bt_verbose) {
      std::cerr << std::endl
                << "Error log: " << std::endl
                << log_buf.get() << std::endl;
      if (errno == ENOSPC)
      {
        errmsg << "Error: Failed to load program, verification log buffer "
               << "not big enough, try increasing the BPFTRACE_LOG_SIZE "
               << "environment variable beyond the current value of "
               << probe_.log_size << " bytes";

        throw std::runtime_error(errmsg.str());
      }
    }

    // try to identify an illegal helper call
    if (std::string(log_buf.get())
            .find("helper call is not allowed in probe") != std::string::npos)
    {
      // get helper function name and id
      std::cmatch m;
      if (std::regex_search(log_buf.get(), m, helper_verifier_error_re))
      {
        throw HelperVerifierError(static_cast<libbpf::bpf_func_id>(
                                      std::stoi(m[2].str())),
                                  m[1].str());
      }
    }

    errmsg << "Error loading program: " << probe_.name
           << (bt_verbose ? "" : " (try -v)");
    if (probe_.orig_name != probe_.name)
    {
      // one attachpoint in a multi-attachpoint (wildcard or list) probe failed,
      // print a warning but continue
      LOG(WARNING) << errmsg.str() << ", skipping.";
      return;
    }
    else
      // explicit match failed, fail hard
      throw std::runtime_error(errmsg.str());
  }

  if (bt_verbose) {
    struct bpf_prog_info info = {};
    uint32_t info_len = sizeof(info);
    int ret;

    ret = bpf_obj_get_info(progfd_, &info, &info_len);
    if (ret == 0) {
      std::cout << std::endl << "Program ID: " << info.id << std::endl;
    }
    std::cout << std::endl
              << "The verifier log: " << std::endl
              << log_buf.get() << std::endl;
  }

  cache_progfd();
}

static inline uint64_t ptr_to_u64(const void *ptr)
{
  return (uint64_t)(unsigned long)ptr;
}

void AttachedProbe::attach_multi_kprobe(void)
{
  DECLARE_LIBBPF_OPTS(bpf_link_create_opts, opts);
  std::vector<const char *> syms;
  unsigned int i = 0;

  for (i = 0; i < probe_.funcs.size(); i++)
  {
    syms.push_back(probe_.funcs[i].c_str());
  }

  opts.kprobe_multi.syms = syms.data();
  opts.kprobe_multi.cnt = syms.size();
  opts.kprobe_multi.flags = probe_.type == ProbeType::kretprobe
                                ? BPF_F_KPROBE_MULTI_RETURN
                                : 0;

  if (bt_verbose)
  {
    std::cout << "Attaching to " << probe_.funcs.size() << " functions"
              << std::endl;

    if (bt_verbose2)
    {
      for (i = 0; i < opts.kprobe_multi.cnt; i++)
      {
        std::cout << " " << syms[i] << std::endl;
      }
    }
  }

  linkfd_ = bpf_link_create(progfd_,
                            0,
                            static_cast<enum ::bpf_attach_type>(
                                libbpf::BPF_TRACE_KPROBE_MULTI),
                            &opts);
  if (linkfd_ < 0)
  {
    throw std::runtime_error("Error attaching probe: '" + probe_.name + "'");
  }
}

void AttachedProbe::attach_kprobe(bool safe_mode)
{
  if (!probe_.funcs.empty())
  {
    attach_multi_kprobe();
    return;
  }

  resolve_offset_kprobe(safe_mode);
  int perf_event_fd = bpf_attach_kprobe(progfd_,
                                        attachtype(probe_.type),
                                        eventname().c_str(),
                                        probe_.attach_point.c_str(),
                                        offset_,
                                        0);

  if (perf_event_fd < 0) {
    if (probe_.orig_name != probe_.name) {
      // a wildcard expansion couldn't probe something, just print a warning
      // as this is normal for some kernel functions (eg, do_debug())
      LOG(WARNING) << "could not attach probe " << probe_.name << ", skipping.";
    } else {
      if (errno == EILSEQ)
        LOG(ERROR) << "Possible attachment attempt in the middle of an "
                      "instruction, try a different offset.";
      // an explicit match failed, so fail as the user must have wanted it
      throw std::runtime_error("Error attaching probe: '" + probe_.name + "'");
    }
  }

  perf_event_fds_.push_back(perf_event_fd);
}

#ifdef HAVE_LIBBPF_UPROBE_MULTI
struct bcc_sym_cb_data
{
  std::vector<std::string> &syms;
  std::set<uint64_t> &offsets;
};

static int bcc_sym_cb(const char *symname, uint64_t start, uint64_t, void *p)
{
  struct bcc_sym_cb_data *data = static_cast<struct bcc_sym_cb_data *>(p);
  std::vector<std::string> &syms = data->syms;

  if (std::binary_search(syms.begin(), syms.end(), symname))
  {
    data->offsets.insert(start);
  }

  return 0;
}

struct addr_offset
{
  uint64_t addr;
  uint64_t offset;
};

static int bcc_load_cb(uint64_t v_addr,
                       uint64_t mem_sz,
                       uint64_t file_offset,
                       void *p)
{
  std::vector<struct addr_offset> *addrs =
      static_cast<std::vector<struct addr_offset> *>(p);

  for (auto &a : *addrs)
  {
    if (a.addr >= v_addr && a.addr < (v_addr + mem_sz))
    {
      a.offset = a.addr - v_addr + file_offset;
    }
  }

  return 0;
}

static void resolve_offset_uprobe_multi(const std::string &path,
                                        const std::string &probe_name,
                                        const std::vector<std::string> &funcs,
                                        std::vector<std::string> &syms,
                                        std::vector<uint64_t> &offsets)
{
  struct bcc_symbol_option option = {};
  int err;

  // Parse symbols names into syms vector
  for (const std::string &func : funcs)
  {
    auto pos = func.find(':');

    if (pos == std::string::npos)
    {
      throw std::runtime_error("Error resolving probe: '" + probe_name + "'");
    }

    syms.push_back(func.substr(pos + 1));
  }

  std::sort(std::begin(syms), std::end(syms));

  option.use_debug_file = 1;
  option.use_symbol_type = 0xffffffff;

  std::vector<struct addr_offset> addrs;
  std::set<uint64_t> set;
  struct bcc_sym_cb_data data = {
    .syms = syms,
    .offsets = set,
  };

  // Resolve symbols into addresses
  err = bcc_elf_foreach_sym(path.c_str(), bcc_sym_cb, &option, &data);
  if (err)
  {
    throw std::runtime_error("Failed to list symbols for probe: '" +
                             probe_name + "'");
  }

  for (auto a : set)
  {
    struct addr_offset addr = {
      .addr = a,
      .offset = 0x0,
    };

    addrs.push_back(addr);
  }

  // Translate addresses into offsets
  err = bcc_elf_foreach_load_section(path.c_str(), bcc_load_cb, &addrs);
  if (err)
  {
    throw std::runtime_error("Failed to resolve symbols offsets for probe: '" +
                             probe_name + "'");
  }

  for (auto a : addrs)
  {
    offsets.push_back(a.offset);
  }
}

void AttachedProbe::attach_multi_uprobe(void)
{
  std::vector<std::string> syms;
  std::vector<uint64_t> offsets;
  unsigned int i;

  // Resolve probe_.funcs into offsets and syms vector
  resolve_offset_uprobe_multi(
      probe_.path, probe_.name, probe_.funcs, syms, offsets);

  // Attach uprobe through uprobe_multi link
  DECLARE_LIBBPF_OPTS(bpf_link_create_opts, opts);

  opts.uprobe_multi.path = probe_.path.c_str();
  opts.uprobe_multi.offsets = offsets.data();
  opts.uprobe_multi.cnt = offsets.size();
  opts.uprobe_multi.flags = probe_.type == ProbeType::uretprobe
                                ? BPF_F_UPROBE_MULTI_RETURN
                                : 0;
  if (bt_verbose)
  {
    std::cout << "Attaching to " << probe_.funcs.size() << " functions"
              << std::endl;

    if (bt_verbose2)
    {
      for (i = 0; i < syms.size(); i++)
      {
        std::cout << probe_.path << ":" << syms[i] << std::endl;
      }
    }
  }

  linkfd_ = bpf_link_create(progfd_,
                            0,
                            static_cast<enum ::bpf_attach_type>(
                                libbpf::BPF_TRACE_UPROBE_MULTI),
                            &opts);
  if (linkfd_ < 0)
  {
    throw std::runtime_error("Error attaching probe: '" + probe_.name + "'");
  }
}
#else
void AttachedProbe::attach_multi_uprobe(void)
{
}
#endif // HAVE_LIBBPF_UPROBE_MULTI

void AttachedProbe::attach_uprobe(bool safe_mode)
{
  if (!probe_.funcs.empty())
  {
    attach_multi_uprobe();
    return;
  }

  if (!resolve_offset_uprobe(safe_mode))
    return;

  int perf_event_fd = bpf_attach_uprobe(progfd_,
                                        attachtype(probe_.type),
                                        eventname().c_str(),
                                        probe_.path.c_str(),
                                        offset_,
                                        probe_.pid,
                                        0);

  if (perf_event_fd < 0)
    throw std::runtime_error("Error attaching probe: " + probe_.name);

  perf_event_fds_.push_back(perf_event_fd);
}

int AttachedProbe::usdt_sem_up_manual(const std::string &fn_name, void *ctx)
{
  int err;

#ifdef BCC_USDT_HAS_FULLY_SPECIFIED_PROBE
  if (probe_.ns == "")
    err = bcc_usdt_enable_probe(ctx,
                                probe_.attach_point.c_str(),
                                fn_name.c_str());
  else
    err = bcc_usdt_enable_fully_specified_probe(
        ctx, probe_.ns.c_str(), probe_.attach_point.c_str(), fn_name.c_str());
#else
  err = bcc_usdt_enable_probe(ctx,
                              probe_.attach_point.c_str(),
                              fn_name.c_str());
#endif // BCC_USDT_HAS_FULLY_SPECIFIED_PROBE

  // Defer context destruction until probes are detached b/c context
  // destruction will decrement usdt semaphore count.
  usdt_destructor_ = [ctx]() { bcc_usdt_close(ctx); };

  return err;
}

int AttachedProbe::usdt_sem_up_manual_addsem(int pid,
                                             const std::string &fn_name,
                                             void *ctx)
{
  // NB: we are careful to capture by value here everything that will not
  // be available in AttachedProbe destructor.
  auto addsem = [this, fn_name](void *c, int16_t val) -> int {
    if (this->probe_.ns == "")
      return bcc_usdt_addsem_probe(
          c, this->probe_.attach_point.c_str(), fn_name.c_str(), val);
    else
      return bcc_usdt_addsem_fully_specified_probe(
          c,
          this->probe_.ns.c_str(),
          this->probe_.attach_point.c_str(),
          fn_name.c_str(),
          val);
  };

  // Set destructor to decrement the semaphore count
  usdt_destructor_ = [pid, addsem]() {
    void *c = bcc_usdt_new_frompid(pid, nullptr);
    if (!c)
      return;

    addsem(c, -1);
    bcc_usdt_close(c);
  };

  // Use semaphore increment API to avoid having to hold onto the usdt context
  // for the entire tracing session. Reason we do it this way instead of
  // holding onto usdt context is b/c each usdt context can take lots of memory
  // (~10MB). This, coupled with --usdt-file-activation and tracees that have a
  // forking model can cause bpftrace to use huge amounts of memory if we hold
  // onto the contexts.
  int err = addsem(ctx, +1);

  // Now close the context to save some memory
  bcc_usdt_close(ctx);

  return err;
}

int AttachedProbe::usdt_sem_up([[maybe_unused]] BPFfeature &feature,
                               [[maybe_unused]] int pid,
                               const std::string &fn_name,
                               void *ctx)
{
  // If we have BCC and kernel support for uprobe refcnt API, then we don't
  // need to do anything here. The kernel will increment the semaphore count
  // for us when we provide the semaphore offset.
  if (feature.has_uprobe_refcnt())
  {
    bcc_usdt_close(ctx);
    return 0;
  }

  return usdt_sem_up_manual_addsem(pid, fn_name, ctx);
}

void AttachedProbe::attach_usdt(int pid, BPFfeature &feature)
{
  struct bcc_usdt_location loc = {};
  int err;
  void *ctx;
  // TODO: fn_name may need a unique suffix for each attachment on the same
  // probe:
  std::string fn_name = "probe_" + probe_.attach_point + "_1";

  if (pid)
  {
    // FIXME when iovisor/bcc#2064 is merged, optionally pass probe_.path
    ctx = bcc_usdt_new_frompid(pid, nullptr);
    if (!ctx)
      throw std::runtime_error(
          "Error initializing context for probe: " + probe_.name +
          ", for PID: " + std::to_string(pid));
  }
  else
  {
    ctx = bcc_usdt_new_frompath(probe_.path.c_str());
    if (!ctx)
      throw std::runtime_error("Error initializing context for probe: " +
                               probe_.name);
  }

  // Resolve location of usdt probe
  auto u = USDTHelper::find(pid, probe_.path, probe_.ns, probe_.attach_point);
  if (!u.has_value())
    throw std::runtime_error("Failed to find usdt probe: " + eventname());
  probe_.path = u->path;

  err = bcc_usdt_get_location(ctx,
                              probe_.ns.c_str(),
                              probe_.attach_point.c_str(),
                              probe_.usdt_location_idx,
                              &loc);
  if (err)
    throw std::runtime_error("Error finding location for probe: " +
                             probe_.name);
  probe_.loc = loc.address;

  offset_ = resolve_offset(probe_.path, probe_.attach_point, probe_.loc);

  // Should be 0 if there's no semaphore
  //
  // Cast to 32 bits b/c kernel API only takes 32 bit offset
  [[maybe_unused]] auto semaphore_offset = static_cast<uint32_t>(
      u->semaphore_offset);

  // Increment the semaphore count (will noop if no semaphore)
  //
  // NB: Do *not* use `ctx` after this call. It may either be open or closed,
  // depending on which path was taken.
  err = usdt_sem_up(feature, pid, fn_name, ctx);

  if (err)
  {
    std::string errstr;
    errstr += "Error finding or enabling probe: " + probe_.name;
    errstr += '\n';
    errstr +=
        "Try using -p or --usdt-file-activation if there's USDT semaphores";
    throw std::runtime_error(errstr);
  }

  int perf_event_fd =
      bpf_attach_uprobe(progfd_,
                        attachtype(probe_.type),
                        eventname().c_str(),
                        probe_.path.c_str(),
                        offset_,
                        pid == 0 ? -1 : pid,
                        semaphore_offset);

  if (perf_event_fd < 0)
  {
    if (pid)
      throw std::runtime_error("Error attaching probe: " + probe_.name +
                               ", to PID: " + std::to_string(pid));
    else
      throw std::runtime_error("Error attaching probe: " + probe_.name);
  }

  perf_event_fds_.push_back(perf_event_fd);
}

void AttachedProbe::attach_tracepoint()
{
  int perf_event_fd = bpf_attach_tracepoint(progfd_, probe_.path.c_str(),
      eventname().c_str());

  if (perf_event_fd < 0 && probe_.name == probe_.orig_name)
  {
    // do not fail if there are other attach points where attaching may succeed
    throw std::runtime_error("Error attaching probe: " + probe_.name);
  }

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
    LOG(FATAL) << "invalid profile path \"" << probe_.path << "\"";
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

  uint64_t period = 0, freq = 0;
  if (probe_.path == "s")
  {
    period = probe_.freq * 1e9;
  }
  else if (probe_.path == "ms")
  {
    period = probe_.freq * 1e6;
  }
  else if (probe_.path == "us")
  {
    period = probe_.freq * 1e3;
  }
  else if (probe_.path == "hz")
  {
    freq = probe_.freq;
  }
  else
  {
    LOG(FATAL) << "invalid interval path \"" << probe_.path << "\"";
  }

  int perf_event_fd = bpf_attach_perf_event(progfd_,
                                            PERF_TYPE_SOFTWARE,
                                            PERF_COUNT_SW_CPU_CLOCK,
                                            period,
                                            freq,
                                            pid,
                                            cpu,
                                            group_fd);

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

void AttachedProbe::attach_watchpoint(int pid, const std::string& mode)
{
  struct perf_event_attr attr = {};
  attr.type = PERF_TYPE_BREAKPOINT;
  attr.size = sizeof(struct perf_event_attr);
  attr.config = 0;

  attr.bp_type = HW_BREAKPOINT_EMPTY;
  for (const char c : mode) {
    if (c == 'r')
      attr.bp_type |= HW_BREAKPOINT_R;
    else if (c == 'w')
      attr.bp_type |= HW_BREAKPOINT_W;
    else if (c == 'x')
      attr.bp_type |= HW_BREAKPOINT_X;
  }

  attr.bp_addr = probe_.address;
  attr.bp_len = probe_.len;
  // Generate a notification every 1 event; we care about every event
  attr.sample_period = 1;

  std::vector<int> cpus;
  if (pid >= 1)
  {
    cpus = { -1 };
  }
  else
  {
    cpus = get_online_cpus();
    pid = -1;
  }

  for (int cpu : cpus)
  {
    // We copy paste the code from bcc's bpf_attach_perf_event_raw here
    // because we need to know the exact error codes (and also we don't
    // want bcc's noisy error messages).
    int perf_event_fd = syscall(
        __NR_perf_event_open, &attr, pid, cpu, -1, PERF_FLAG_FD_CLOEXEC);
    if (perf_event_fd < 0)
    {
      if (errno == ENOSPC)
        throw EnospcException("No more HW registers left");
      else
        throw std::system_error(errno,
                                std::generic_category(),
                                "Error attaching probe: " + probe_.name);
    }
    if (ioctl(perf_event_fd, PERF_EVENT_IOC_SET_BPF, progfd_) != 0)
    {
      close(perf_event_fd);
      throw std::system_error(errno,
                              std::generic_category(),
                              "Error attaching probe: " + probe_.name);
    }
    if (ioctl(perf_event_fd, PERF_EVENT_IOC_ENABLE, 0) != 0)
    {
      close(perf_event_fd);
      throw std::system_error(errno,
                              std::generic_category(),
                              "Error attaching probe: " + probe_.name);
    }

    perf_event_fds_.push_back(perf_event_fd);
  }
}

} // namespace bpftrace
