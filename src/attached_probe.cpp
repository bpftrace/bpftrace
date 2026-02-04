#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <algorithm>
#include <cstring>
#include <elf.h>
#include <fcntl.h>
#include <filesystem>
#include <iostream>
#include <linux/hw_breakpoint.h>
#include <linux/limits.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <utility>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "attached_probe.h"
#include "bpftrace.h"
#include "disasm.h"
#include "log.h"
#include "util/bpf_names.h"
#include "util/cpus.h"
#include "util/exceptions.h"
#include "util/kernel.h"
#include "util/symbols.h"

namespace bpftrace {

char AttachError::ID;

void AttachError::log(llvm::raw_ostream &OS) const
{
  OS << msg_;
}

bool is_return_type(ProbeType t)
{
  // clang-format off
  switch (t)
  {
    case ProbeType::kprobe:    return false;  break;
    case ProbeType::kretprobe: return true; break;
    case ProbeType::special:   return false;  break;
    case ProbeType::test:      return false;  break;
    case ProbeType::benchmark: return false;  break;
    case ProbeType::uprobe:    return false;  break;
    case ProbeType::uretprobe: return true; break;
    case ProbeType::usdt:      return false;  break;
    default:
      LOG(BUG) << "invalid probe type \"" << t << "\"";
  }
  // clang-format on
}

bpf_prog_type progtype(ProbeType t)
{
  switch (t) {
      // clang-format off
    case ProbeType::special:    return BPF_PROG_TYPE_RAW_TRACEPOINT; break;
    case ProbeType::test:       return BPF_PROG_TYPE_XDP; break;
    case ProbeType::benchmark:  return BPF_PROG_TYPE_XDP; break;
    case ProbeType::kprobe:     return BPF_PROG_TYPE_KPROBE; break;
    case ProbeType::kretprobe:  return BPF_PROG_TYPE_KPROBE; break;
    case ProbeType::uprobe:     return BPF_PROG_TYPE_KPROBE; break;
    case ProbeType::uretprobe:  return BPF_PROG_TYPE_KPROBE; break;
    case ProbeType::usdt:       return BPF_PROG_TYPE_KPROBE; break;
    case ProbeType::tracepoint: return BPF_PROG_TYPE_TRACEPOINT; break;
    case ProbeType::profile:    return BPF_PROG_TYPE_PERF_EVENT; break;
    case ProbeType::interval:   return BPF_PROG_TYPE_PERF_EVENT; break;
    case ProbeType::software:   return BPF_PROG_TYPE_PERF_EVENT; break;
    case ProbeType::watchpoint: return BPF_PROG_TYPE_PERF_EVENT; break;
    case ProbeType::hardware:   return BPF_PROG_TYPE_PERF_EVENT; break;
    case ProbeType::fentry:     return BPF_PROG_TYPE_TRACING; break;
    case ProbeType::fexit:      return BPF_PROG_TYPE_TRACING; break;
    case ProbeType::iter:       return BPF_PROG_TYPE_TRACING; break;
    case ProbeType::rawtracepoint: return BPF_PROG_TYPE_TRACING; break;
    // clang-format on
    case ProbeType::invalid:
      LOG(BUG) << "program type invalid";
  }

  return {}; // unreached
}

std::string progtypeName(bpf_prog_type t)
{
  switch (t) {
      // clang-format off
    case BPF_PROG_TYPE_KPROBE:     return "BPF_PROG_TYPE_KPROBE";     break;
    case BPF_PROG_TYPE_TRACEPOINT: return "BPF_PROG_TYPE_TRACEPOINT"; break;
    case BPF_PROG_TYPE_PERF_EVENT: return "BPF_PROG_TYPE_PERF_EVENT"; break;
    case BPF_PROG_TYPE_TRACING:    return "BPF_PROG_TYPE_TRACING";    break;
    // clang-format on
    default:
      LOG(BUG) << "invalid program type: " << t;
  }
}

std::string eventprefix(ProbeType t)
{
  return is_return_type(t) ? "r_" : "p_";
}

std::string eventname(const Probe &probe, uint64_t offset)
{
  std::ostringstream offset_str;
  std::string index_str = "_" + std::to_string(probe.index);
  switch (probe.type) {
    case ProbeType::kprobe:
    case ProbeType::kretprobe:
    case ProbeType::rawtracepoint:
      offset_str << std::hex << offset;
      return eventprefix(probe.type) +
             util::sanitise_bpf_program_name(probe.attach_point) + "_" +
             offset_str.str() + index_str;
    case ProbeType::uprobe:
    case ProbeType::uretprobe:
    case ProbeType::usdt:
      offset_str << std::hex << offset;
      return eventprefix(probe.type) +
             util::sanitise_bpf_program_name(probe.path) + "_" +
             offset_str.str() + index_str;
    case ProbeType::tracepoint:
      return probe.attach_point;
    default:
      LOG(BUG) << "invalid eventname probe \"" << probe.type << "\"";
  }
}

Result<uint64_t> resolve_offset_kprobe(Probe &probe)
{
  uint64_t offset = probe.func_offset;

  // If we are using only the symbol, we don't need to check the offset.
  bool is_symbol_kprobe = !probe.attach_point.empty();
  if (is_symbol_kprobe && probe.func_offset == 0)
    return offset;

  // Setup the symbol to resolve, either using the address or the name.
  struct symbol sym = {};
  if (is_symbol_kprobe)
    sym.name = probe.attach_point;
  else
    sym.address = probe.address;

  auto path = find_vmlinux(&sym);
  if (!path.has_value()) {
    if (!is_symbol_kprobe) {
      return make_error<AttachError>("Could not resolve address: " +
                                     std::to_string(probe.address));
    }

    LOG(V1) << "Could not resolve symbol " << probe.attach_point
            << ". Skipping usermode offset checking.";
    LOG(V1) << "The kernel will verify the safety of the location but "
               "will also allow the offset to be in a different symbol.";
    return offset;
  }

  // Populate probe_ fields according to the resolved symbol.
  if (is_symbol_kprobe) {
    probe.address = sym.start + probe.func_offset;
  } else {
    probe.attach_point = std::move(sym.name);
    if (__builtin_sub_overflow(probe.address, sym.start, &probe.func_offset))
      LOG(BUG) << "Offset before the function bounds ('" << probe.attach_point
               << "' address is " << std::to_string(sym.start) << ")";
    offset = probe.func_offset;
    // Set the name of the probe to the resolved symbol+offset, so that failure
    // to attach can be ignored if the user set ConfigMissingProbes::warn.
    probe.name = "kprobe:" + probe.attach_point + "+" +
                 std::to_string(probe.func_offset);
  }

  if (probe.func_offset >= sym.size) {
    return make_error<AttachError>("Offset outside the function bounds ('" +
                                   probe.attach_point + "' size is " +
                                   std::to_string(sym.size) + ")");
  }
  return offset;
}

Result<uint64_t> resolve_offset(Probe &probe)
{
  bcc_symbol bcc_sym;

  if (bcc_resolve_symname(probe.path.c_str(),
                          probe.attach_point.c_str(),
                          probe.loc,
                          0,
                          nullptr,
                          &bcc_sym)) {
    return make_error<AttachError>("Could not resolve symbol: " + probe.path +
                                   ":" + probe.attach_point);
  }

  // Have to free sym.module, see:
  // https://github.com/iovisor/bcc/blob/ba73657cb8c4dab83dfb89eed4a8b3866255569a/src/cc/bcc_syms.h#L98-L99
  if (bcc_sym.module)
    ::free(const_cast<char *>(bcc_sym.module));

  return bcc_sym.offset;
}

static constexpr std::string_view hint_unsafe =
    "\nUse --unsafe to force attachment. WARNING: This option could lead to "
    "data corruption in the target process.";

Result<> check_alignment(Probe &probe,
                         std::string &symbol,
                         uint64_t sym_offset,
                         uint64_t func_offset,
                         bool safe_mode)
{
  Disasm dasm(probe.path);
  AlignState aligned = dasm.is_aligned(sym_offset, func_offset);

  std::string tmp = probe.path + ":" + symbol + "+" +
                    std::to_string(func_offset);

  switch (aligned) {
    case AlignState::Ok:
      return OK();
    case AlignState::NotAlign:
      if (safe_mode) {
        return make_error<AttachError>(
            "Could not add " + probetypeName(probe.type) +
            " into middle of instruction: " + tmp + std::string{ hint_unsafe });
      } else {
        std::string_view hint;
        LOG(WARNING) << "Unsafe " << probe.type
                     << " in the middle of the instruction: " << tmp << hint;
        return OK();
      }
    case AlignState::Fail:
      if (safe_mode) {
        return make_error<AttachError>(
            "Failed to check if " + probetypeName(probe.type) +
            " is in proper place: " + tmp + std::string{ hint_unsafe });
      } else {
        LOG(WARNING) << "Unchecked " << probe.type << ": " << tmp;
        return OK();
      }
    case AlignState::NotSupp:
      if (safe_mode) {
        return make_error<AttachError>("Can't check if " +
                                       probetypeName(probe.type) +
                                       " is in proper place (compiled without "
                                       "(k|u)probe offset support): " +
                                       tmp + std::string{ hint_unsafe });
      } else {
        LOG(WARNING) << "Unchecked " << probe.type << ": " << tmp;
        return OK();
      }
  }
  return OK();
}

Result<uint64_t> resolve_offset_uprobe(Probe &probe, bool safe_mode)
{
  struct bcc_symbol_option option = {};
  struct symbol sym = {};
  std::string &symbol = probe.attach_point;
  uint64_t func_offset = probe.func_offset;

  sym.name = "";
  option.use_debug_file = 1;
  option.use_symbol_type = BCC_SYM_ALL_TYPES ^ (1 << STT_NOTYPE);

  if (symbol.empty()) {
    sym.address = probe.address;
    bcc_elf_foreach_sym(
        probe.path.c_str(), util::sym_address_cb, &option, &sym);

    if (!sym.start) {
      if (safe_mode) {
        std::stringstream ss;
        ss << "0x" << std::hex << probe.address;
        return make_error<AttachError>(
            "Could not resolve address: " + probe.path + ":" + ss.str());
      } else {
        LOG(WARNING) << "Could not determine instruction boundary for "
                     << probe.name
                     << " (binary appears stripped). Misaligned probes "
                        "can lead to tracee crashes!";
        return probe.address;
      }
    }

    symbol = sym.name;
    func_offset = probe.address - sym.start;
  } else {
    sym.name = symbol;
    bcc_elf_foreach_sym(probe.path.c_str(), util::sym_name_cb, &option, &sym);

    if (!sym.start) {
      return make_error<AttachError>("Could not resolve symbol: " + probe.path +
                                     ":" + symbol);
    }
  }

  if (probe.type == ProbeType::uretprobe && func_offset != 0) {
    return make_error<AttachError>("uretprobes cannot be attached at function "
                                   "offset. (address resolved to: " +
                                   symbol + "+" + std::to_string(func_offset) +
                                   ")");
  }

  if (sym.size == 0 && func_offset == 0) {
    if (safe_mode) {
      return make_error<AttachError>("Could not determine boundary for " +
                                     sym.name + " (symbol has size 0)." +
                                     std::string{ hint_unsafe });
    }
  } else if (func_offset >= sym.size) {
    return make_error<AttachError>("Offset outside the function bounds ('" +
                                   symbol + "' size is " +
                                   std::to_string(sym.size) + ")");
  }

  auto sym_offset = resolve_offset(probe);
  if (!sym_offset) {
    return sym_offset.takeError();
  }

  uint64_t offset = *sym_offset + func_offset;

  // If we are not aligned to the start of the symbol,
  // check if we are on the instruction boundary.
  if (func_offset == 0)
    return offset;

  auto align_ok = check_alignment(
      probe, symbol, *sym_offset, func_offset, safe_mode);

  if (!align_ok) {
    return align_ok.takeError();
  }

  return offset;
}

struct bcc_sym_cb_data {
  std::vector<std::string> &syms;
  std::set<uint64_t> &offsets;
};

static int bcc_sym_cb(const char *symname,
                      uint64_t start,
                      uint64_t /*unused*/,
                      void *p)
{
  auto *data = static_cast<struct bcc_sym_cb_data *>(p);
  std::vector<std::string> &syms = data->syms;

  if (std::ranges::binary_search(syms, symname)) {
    data->offsets.insert(start);
  }

  return 0;
}

struct addr_offset {
  uint64_t addr;
  uint64_t offset;
};

static int bcc_load_cb(uint64_t v_addr,
                       uint64_t mem_sz,
                       uint64_t file_offset,
                       void *p)
{
  auto *addrs = static_cast<std::vector<struct addr_offset> *>(p);

  for (auto &a : *addrs) {
    if (a.addr >= v_addr && a.addr < (v_addr + mem_sz)) {
      a.offset = a.addr - v_addr + file_offset;
    }
  }

  return 0;
}

Result<std::vector<unsigned long>> resolve_offsets_uprobe_multi(
    Probe &probe,
    std::vector<std::string> &syms)
{
  std::vector<unsigned long> offsets;
  struct bcc_symbol_option option = {};
  int err;

  // Parse symbols names into syms vector
  for (const std::string &func : probe.funcs) {
    auto pos = func.find(':');

    if (pos == std::string::npos) {
      return make_error<AttachError>("Error resolving probe: " + probe.name);
    }

    syms.push_back(func.substr(pos + 1));
  }

  std::ranges::sort(syms);

  option.use_debug_file = 1;
  option.use_symbol_type = BCC_SYM_ALL_TYPES ^ (1 << STT_NOTYPE);

  std::vector<struct addr_offset> addrs;
  std::set<uint64_t> set;
  struct bcc_sym_cb_data data = {
    .syms = syms,
    .offsets = set,
  };

  // Resolve symbols into addresses
  err = bcc_elf_foreach_sym(probe.path.c_str(), bcc_sym_cb, &option, &data);
  if (err) {
    return make_error<AttachError>("Failed to list symbols for probe: " +
                                   probe.name);
  }

  for (auto a : set) {
    struct addr_offset addr = {
      .addr = a,
      .offset = 0x0,
    };

    addrs.push_back(addr);
  }

  // Translate addresses into offsets
  err = bcc_elf_foreach_load_section(probe.path.c_str(), bcc_load_cb, &addrs);
  if (err) {
    return make_error<AttachError>(
        "Failed to resolve symbols offsets for probe: " + probe.name);
  }

  for (auto a : addrs) {
    offsets.push_back(a.offset);
  }

  return offsets;
}

class AttachedKprobeProbe : public AttachedProbe {
public:
  static Result<std::unique_ptr<AttachedKprobeProbe>> make(
      Probe &probe,
      const BpfProgram &prog);
  ~AttachedKprobeProbe() override;

  int link_fd() override;

private:
  AttachedKprobeProbe(const Probe &probe, struct bpf_link *link);
  struct bpf_link *link_;
};

AttachedKprobeProbe::AttachedKprobeProbe(const Probe &probe,
                                         struct bpf_link *link)
    : AttachedProbe(probe), link_(link)
{
}

AttachedKprobeProbe::~AttachedKprobeProbe()
{
  if (bpf_link__destroy(link_)) {
    LOG(WARNING) << "failed to destroy link for kprobe probe: "
                 << strerror(errno);
  }
}

int AttachedKprobeProbe::link_fd()
{
  return bpf_link__fd(link_);
}

Result<std::unique_ptr<AttachedKprobeProbe>> AttachedKprobeProbe::make(
    Probe &probe,
    const BpfProgram &prog)
{
  // Construct a string containing "module:function". We don't do any
  // additional checking here because this has already been verified during
  // attachpoint verification. We will automatically propagate any failures
  // to attach form the libbpf layer in the future.
  std::string funcname = probe.attach_point;

  // The kprobe can either be defined by a symbol+offset or an address:
  // For symbol+offset kprobe, we need to check the validity of the offset.
  // For address kprobe, we need to resolve into the symbol+offset and
  // populate `funcname` with the results stored back in the probe.
  bool is_symbol_kprobe = !probe.attach_point.empty();
  auto offset_res = resolve_offset_kprobe(probe);
  if (!offset_res) {
    return offset_res.takeError();
  }
  uint64_t offset = *offset_res;
  if (!is_symbol_kprobe)
    funcname += probe.attach_point;

  DECLARE_LIBBPF_OPTS(bpf_kprobe_opts, opts);
  opts.offset = offset;
  opts.retprobe = probe.type == ProbeType::kretprobe;

  auto *link = bpf_program__attach_kprobe_opts(prog.bpf_prog(),
                                               funcname.c_str(),
                                               &opts);
  if (!link) {
    if (errno == EILSEQ)
      return make_error<AttachError>(
          "Possible attachment attempt in the middle of an instruction, "
          "try a different offset.");
    return make_error<AttachError>();
  }

  return std::unique_ptr<AttachedKprobeProbe>(
      new AttachedKprobeProbe(probe, link));
}

class AttachedMultiKprobeProbe : public AttachedProbe {
public:
  static Result<std::unique_ptr<AttachedMultiKprobeProbe>> make(
      Probe &probe,
      const BpfProgram &prog);
  ~AttachedMultiKprobeProbe() override;

  int link_fd() override;

  size_t probe_count() const override;

private:
  AttachedMultiKprobeProbe(const Probe &probe, int link_fd);
  int link_fd_;
};

AttachedMultiKprobeProbe::AttachedMultiKprobeProbe(const Probe &probe,
                                                   int link_fd)
    : AttachedProbe(probe), link_fd_(link_fd)
{
}

AttachedMultiKprobeProbe::~AttachedMultiKprobeProbe()
{
  close(link_fd_);
}

int AttachedMultiKprobeProbe::link_fd()
{
  return link_fd_;
}

size_t AttachedMultiKprobeProbe::probe_count() const
{
  return probe_.funcs.size();
}

Result<std::unique_ptr<AttachedMultiKprobeProbe>> AttachedMultiKprobeProbe::
    make(Probe &probe, const BpfProgram &prog)
{
  DECLARE_LIBBPF_OPTS(bpf_link_create_opts, opts);
  std::vector<const char *> syms;
  unsigned int i = 0;

  for (const auto &func : probe.funcs)
    syms.push_back(func.c_str());

  opts.kprobe_multi.syms = syms.data();
  opts.kprobe_multi.cnt = syms.size();
  opts.kprobe_multi.flags = probe.type == ProbeType::kretprobe
                                ? BPF_F_KPROBE_MULTI_RETURN
                                : 0;

  if (bt_verbose) {
    LOG(V1) << "Attaching to " << probe.funcs.size() << " functions";
    for (i = 0; i < opts.kprobe_multi.cnt; i++) {
      LOG(V1) << " " << syms[i];
    }
  }

  auto attach_type = probe.is_session ? BPF_TRACE_KPROBE_SESSION
                                      : BPF_TRACE_KPROBE_MULTI;

  int link_fd = bpf_link_create(prog.fd(), 0, attach_type, &opts);
  if (link_fd < 0) {
    return make_error<AttachError>();
  }

  return std::unique_ptr<AttachedMultiKprobeProbe>(
      new AttachedMultiKprobeProbe(probe, link_fd));
}

class AttachedUprobeProbe : public AttachedProbe {
public:
  static Result<std::unique_ptr<AttachedUprobeProbe>> make(
      Probe &probe,
      const BpfProgram &prog,
      std::optional<int> pid,
      bool safe_mode);
  ~AttachedUprobeProbe() override;

  int link_fd() override;

private:
  AttachedUprobeProbe(const Probe &probe, struct bpf_link *link);

  struct bpf_link *link_;
};

AttachedUprobeProbe::AttachedUprobeProbe(const Probe &probe,
                                         struct bpf_link *link)
    : AttachedProbe(probe), link_(link)
{
}

AttachedUprobeProbe::~AttachedUprobeProbe()
{
  if (bpf_link__destroy(link_))
    LOG(WARNING) << "failed to destroy link for uprobe probe: "
                 << strerror(errno);
}

int AttachedUprobeProbe::link_fd()
{
  return bpf_link__fd(link_);
}

Result<std::unique_ptr<AttachedUprobeProbe>> AttachedUprobeProbe::make(
    Probe &probe,
    const BpfProgram &prog,
    std::optional<int> pid,
    bool safe_mode)
{
  auto offset_res = resolve_offset_uprobe(probe, safe_mode);
  if (!offset_res) {
    return offset_res.takeError();
  }

  DECLARE_LIBBPF_OPTS(bpf_uprobe_opts, opts);
  opts.retprobe = probe.type == ProbeType::uretprobe;

  auto *link = bpf_program__attach_uprobe_opts(prog.bpf_prog(),
                                               pid.has_value() ? *pid : -1,
                                               probe.path.c_str(),
                                               *offset_res,
                                               &opts);

  if (!link) {
    return make_error<AttachError>();
  }

  return std::unique_ptr<AttachedUprobeProbe>(
      new AttachedUprobeProbe(probe, link));
}

class AttachedMultiUprobeProbe : public AttachedProbe {
public:
  static Result<std::unique_ptr<AttachedMultiUprobeProbe>> make(
      Probe &probe,
      const BpfProgram &prog,
      std::optional<int> pid);
  ~AttachedMultiUprobeProbe() override;

  size_t probe_count() const override;

private:
  AttachedMultiUprobeProbe(const Probe &probe, int link_fd);
  int link_fd_;
};

AttachedMultiUprobeProbe::AttachedMultiUprobeProbe(const Probe &probe,
                                                   int link_fd)
    : AttachedProbe(probe), link_fd_(link_fd)
{
}

AttachedMultiUprobeProbe::~AttachedMultiUprobeProbe()
{
  close(link_fd_);
}

size_t AttachedMultiUprobeProbe::probe_count() const
{
  return probe_.funcs.size();
}

Result<std::unique_ptr<AttachedMultiUprobeProbe>> AttachedMultiUprobeProbe::
    make(Probe &probe, const BpfProgram &prog, std::optional<int> pid)
{
  std::vector<std::string> syms;
  unsigned int i;

  // Resolve probe_.funcs into offsets and syms vector
  auto offset_res = resolve_offsets_uprobe_multi(probe, syms);
  if (!offset_res) {
    return offset_res.takeError();
  }

  // Attach uprobe through uprobe_multi link
  DECLARE_LIBBPF_OPTS(bpf_link_create_opts, opts);
  opts.uprobe_multi.path = probe.path.c_str();
  opts.uprobe_multi.offsets = offset_res->data();
  opts.uprobe_multi.cnt = offset_res->size();
  opts.uprobe_multi.flags = probe.type == ProbeType::uretprobe
                                ? BPF_F_UPROBE_MULTI_RETURN
                                : 0;
  if (pid.has_value()) {
    opts.uprobe_multi.pid = *pid;
  }

  if (bt_verbose) {
    LOG(V1) << "Attaching to " << probe.funcs.size() << " functions";
    for (i = 0; i < syms.size(); i++) {
      LOG(V1) << probe.path << ":" << syms[i];
    }
  }

  int link_fd = bpf_link_create(prog.fd(), 0, BPF_TRACE_UPROBE_MULTI, &opts);

  if (link_fd < 0) {
    return make_error<AttachError>();
  }

  return std::unique_ptr<AttachedMultiUprobeProbe>(
      new AttachedMultiUprobeProbe(probe, link_fd));
}

class AttachedUSDTProbe : public AttachedProbe {
public:
  static Result<std::unique_ptr<AttachedUSDTProbe>> make(
      Probe &probe,
      const BpfProgram &prog,
      std::optional<int> pid);
  ~AttachedUSDTProbe() override;

  int link_fd() override;

private:
  AttachedUSDTProbe(const Probe &probe, struct bpf_link *link);
  struct bpf_link *link_;
};

AttachedUSDTProbe::AttachedUSDTProbe(const Probe &probe, struct bpf_link *link)
    : AttachedProbe(probe), link_(link)
{
}

int AttachedUSDTProbe::link_fd()
{
  return bpf_link__fd(link_);
}

AttachedUSDTProbe::~AttachedUSDTProbe()
{
  if (bpf_link__destroy(link_))
    LOG(WARNING) << "failed to destroy link for usdt probe: "
                 << strerror(errno);
}

Result<std::unique_ptr<AttachedUSDTProbe>> AttachedUSDTProbe::make(
    Probe &probe,
    const BpfProgram &prog,
    std::optional<int> pid)
{
  auto *link = bpf_program__attach_usdt(prog.bpf_prog(),
                                        pid.has_value() ? *pid : -1,
                                        probe.path.c_str(),
                                        probe.ns.c_str(),
                                        probe.attach_point.c_str(),
                                        nullptr);

  if (!link) {
    char bpf_error_msg[128];
    int res = libbpf_strerror(errno, bpf_error_msg, sizeof(bpf_error_msg));
    if (res) {
      return make_error<AttachError>("Failed to attach usdt probe: " +
                                     std::string(std::strerror(errno)));
    } else {
      return make_error<AttachError>("Failed to attach usdt probe: " +
                                     std::string(bpf_error_msg));
    }
  }

  return std::unique_ptr<AttachedUSDTProbe>(new AttachedUSDTProbe(probe, link));
}

class AttachedTracepointProbe : public AttachedProbe {
public:
  static Result<std::unique_ptr<AttachedTracepointProbe>> make(
      Probe &probe,
      const BpfProgram &prog);
  ~AttachedTracepointProbe() override;

private:
  AttachedTracepointProbe(const Probe &probe, struct bpf_link *link);
  struct bpf_link *link_;
};

AttachedTracepointProbe::AttachedTracepointProbe(const Probe &probe,
                                                 struct bpf_link *link)
    : AttachedProbe(probe), link_(link)
{
}

AttachedTracepointProbe::~AttachedTracepointProbe()
{
  if (bpf_link__destroy(link_)) {
    LOG(WARNING) << "failed to destroy link for tracepiont probe: "
                 << strerror(errno);
  }
}

Result<std::unique_ptr<AttachedTracepointProbe>> AttachedTracepointProbe::make(
    Probe &probe,
    const BpfProgram &prog)
{
  auto *link = bpf_program__attach_tracepoint(prog.bpf_prog(),
                                              probe.path.c_str(),
                                              eventname(probe, 0).c_str());

  if (!link) {
    return make_error<AttachError>();
  }

  return std::unique_ptr<AttachedTracepointProbe>(
      new AttachedTracepointProbe(probe, link));
}

int open_perf_event(uint32_t ev_type,
                    uint32_t ev_config,
                    uint64_t sample_period,
                    uint64_t sample_freq,
                    pid_t pid,
                    int cpu,
                    int group_fd)
{
  if (sample_period > 0 && sample_freq > 0) {
    LOG(BUG) << "Exactly one of sample_period / sample_freq should be set";
    return -1;
  }

  struct perf_event_attr attr = {};
  attr.type = ev_type;
  attr.size = sizeof(struct perf_event_attr);
  attr.config = ev_config;
  if (sample_freq > 0) {
    attr.freq = 1;
    attr.sample_freq = sample_freq;
  } else {
    attr.sample_period = sample_period;
  }
  if (pid > 0)
    attr.inherit = 1;

  return syscall(
      __NR_perf_event_open, &attr, pid, cpu, group_fd, PERF_FLAG_FD_CLOEXEC);
}

class AttachedProfileProbe : public AttachedProbe {
public:
  static Result<std::unique_ptr<AttachedProfileProbe>> make(
      Probe &probe,
      const BpfProgram &prog,
      std::optional<int> pid);
  ~AttachedProfileProbe() override;

private:
  AttachedProfileProbe(const Probe &probe,
                       std::vector<struct bpf_link *> links);
  std::vector<struct bpf_link *> links_;
};

AttachedProfileProbe::AttachedProfileProbe(const Probe &probe,
                                           std::vector<struct bpf_link *> links)
    : AttachedProbe(probe), links_(std::move(links))
{
}

AttachedProfileProbe::~AttachedProfileProbe()
{
  for (struct bpf_link *link : links_) {
    if (bpf_link__destroy(link))
      LOG(WARNING) << "failed to destroy link for profile probe: "
                   << strerror(errno);
  }
}

Result<std::unique_ptr<AttachedProfileProbe>> AttachedProfileProbe::make(
    Probe &probe,
    const BpfProgram &prog,
    std::optional<int> pid)
{
  int group_fd = -1;

  uint64_t period, freq;
  if (probe.path == "hz") {
    period = 0;
    freq = probe.freq;
  } else if (probe.path == "s") {
    period = probe.freq * 1e9;
    freq = 0;
  } else if (probe.path == "ms") {
    period = probe.freq * 1e6;
    freq = 0;
  } else if (probe.path == "us") {
    period = probe.freq * 1e3;
    freq = 0;
  } else {
    return make_error<AttachError>("invalid profile path \"" + probe.path +
                                   "\"");
  }

  bool has_error = false;
  std::vector<struct bpf_link *> links;
  std::vector<int> cpus = util::get_online_cpus();
  for (int cpu : cpus) {
    int perf_event_fd = open_perf_event(PERF_TYPE_SOFTWARE,
                                        PERF_COUNT_SW_CPU_CLOCK,
                                        period,
                                        freq,
                                        pid.has_value() ? *pid : -1,
                                        cpu,
                                        group_fd);

    if (perf_event_fd < 0) {
      has_error = true;
      break;
    }

    auto *link = bpf_program__attach_perf_event(prog.bpf_prog(), perf_event_fd);
    if (!link) {
      close(perf_event_fd);
      has_error = true;
      break;
    }

    links.push_back(link);
  }

  if (has_error) {
    for (struct bpf_link *link : links) {
      if (bpf_link__destroy(link))
        LOG(WARNING) << "failed to destroy link for profile probe: "
                     << strerror(errno);
    }
    return make_error<AttachError>();
  }

  return std::unique_ptr<AttachedProfileProbe>(
      new AttachedProfileProbe(probe, links));
}

class AttachedIntervalProbe : public AttachedProbe {
public:
  static Result<std::unique_ptr<AttachedIntervalProbe>> make(
      Probe &probe,
      const BpfProgram &prog);
  ~AttachedIntervalProbe() override;

  int link_fd() override;

private:
  AttachedIntervalProbe(const Probe &probe, struct bpf_link *link);
  struct bpf_link *link_;
};

AttachedIntervalProbe::AttachedIntervalProbe(const Probe &probe,
                                             struct bpf_link *link)
    : AttachedProbe(probe), link_(link)
{
}

AttachedIntervalProbe::~AttachedIntervalProbe()
{
  if (bpf_link__destroy(link_))
    LOG(WARNING) << "failed to destroy link for interval probe: "
                 << strerror(errno);
}

int AttachedIntervalProbe::link_fd()
{
  return bpf_link__fd(link_);
}

Result<std::unique_ptr<AttachedIntervalProbe>> AttachedIntervalProbe::make(
    Probe &probe,
    const BpfProgram &prog)
{
  int group_fd = -1;
  int cpu = 0;
  std::vector<int> cpus = util::get_online_cpus();
  if (!cpus.empty())
    cpu = cpus[0];

  uint64_t period = 0, freq = 0;
  if (probe.path == "s") {
    period = probe.freq * 1e9;
  } else if (probe.path == "ms") {
    period = probe.freq * 1e6;
  } else if (probe.path == "us") {
    period = probe.freq * 1e3;
  } else if (probe.path == "hz") {
    freq = probe.freq;
  } else {
    return make_error<AttachError>("invalid interval path \"" + probe.path +
                                   "\"");
  }

  int perf_event_fd = open_perf_event(PERF_TYPE_SOFTWARE,
                                      PERF_COUNT_SW_CPU_CLOCK,
                                      period,
                                      freq,
                                      -1,
                                      cpu,
                                      group_fd);

  if (perf_event_fd < 0) {
    return make_error<AttachError>();
  }

  auto *link = bpf_program__attach_perf_event(prog.bpf_prog(), perf_event_fd);
  if (!link) {
    close(perf_event_fd);
    return make_error<AttachError>();
  }

  return std::unique_ptr<AttachedIntervalProbe>(
      new AttachedIntervalProbe(probe, link));
}

class AttachedSoftwareProbe : public AttachedProbe {
public:
  static Result<std::unique_ptr<AttachedSoftwareProbe>> make(
      Probe &probe,
      const BpfProgram &prog,
      std::optional<int> pid);
  ~AttachedSoftwareProbe() override;

private:
  AttachedSoftwareProbe(const Probe &probe,
                        std::vector<struct bpf_link *> links);
  std::vector<struct bpf_link *> links_;
};

AttachedSoftwareProbe::AttachedSoftwareProbe(
    const Probe &probe,
    std::vector<struct bpf_link *> links)
    : AttachedProbe(probe), links_(std::move(links))
{
}

AttachedSoftwareProbe::~AttachedSoftwareProbe()
{
  for (struct bpf_link *link : links_) {
    if (bpf_link__destroy(link))
      LOG(WARNING) << "failed to destroy link for software probe: "
                   << strerror(errno);
  }
}

Result<std::unique_ptr<AttachedSoftwareProbe>> AttachedSoftwareProbe::make(
    Probe &probe,
    const BpfProgram &prog,
    std::optional<int> pid)
{
  int group_fd = -1;

  uint64_t period = probe.freq;
  uint64_t defaultp = 1;
  uint32_t type = 0;

  // from linux/perf_event.h, with aliases from perf:
  for (const auto &probeListItem : SW_PROBE_LIST) {
    if (probe.path == probeListItem.path || probe.path == probeListItem.alias) {
      type = probeListItem.type;
      defaultp = probeListItem.defaultp;
    }
  }

  if (period == 0)
    period = defaultp;

  bool has_error = false;
  std::vector<struct bpf_link *> links;
  std::vector<int> cpus = util::get_online_cpus();
  for (int cpu : cpus) {
    int perf_event_fd = open_perf_event(PERF_TYPE_SOFTWARE,
                                        type,
                                        period,
                                        0,
                                        pid.has_value() ? *pid : -1,
                                        cpu,
                                        group_fd);

    if (perf_event_fd < 0) {
      has_error = true;
      break;
    }

    auto *link = bpf_program__attach_perf_event(prog.bpf_prog(), perf_event_fd);
    if (!link) {
      close(perf_event_fd);
      has_error = true;
      break;
    }

    links.push_back(link);
  }

  if (has_error) {
    for (struct bpf_link *link : links) {
      if (bpf_link__destroy(link))
        LOG(WARNING) << "failed to destroy link for software probe: "
                     << strerror(errno);
    }
    return make_error<AttachError>();
  }

  return std::unique_ptr<AttachedSoftwareProbe>(
      new AttachedSoftwareProbe(probe, links));
}

class AttachedHardwareProbe : public AttachedProbe {
public:
  static Result<std::unique_ptr<AttachedHardwareProbe>> make(
      Probe &probe,
      const BpfProgram &prog,
      std::optional<int> pid);
  ~AttachedHardwareProbe() override;

private:
  AttachedHardwareProbe(const Probe &probe,
                        std::vector<struct bpf_link *> links);
  std::vector<struct bpf_link *> links_;
};

AttachedHardwareProbe::AttachedHardwareProbe(
    const Probe &probe,
    std::vector<struct bpf_link *> links)
    : AttachedProbe(probe), links_(std::move(links))
{
}

AttachedHardwareProbe::~AttachedHardwareProbe()
{
  for (struct bpf_link *link : links_) {
    if (bpf_link__destroy(link))
      LOG(WARNING) << "failed to destroy link for hardware probe: "
                   << strerror(errno);
  }
}

Result<std::unique_ptr<AttachedHardwareProbe>> AttachedHardwareProbe::make(
    Probe &probe,
    const BpfProgram &prog,
    std::optional<int> pid)
{
  int group_fd = -1;

  uint64_t period = probe.freq;
  uint64_t defaultp = 1000000;
  uint32_t type = 0;

  // from linux/perf_event.h, with aliases from perf:
  for (const auto &probeListItem : HW_PROBE_LIST) {
    if (probe.path == probeListItem.path || probe.path == probeListItem.alias) {
      type = probeListItem.type;
      defaultp = probeListItem.defaultp;
    }
  }

  if (period == 0)
    period = defaultp;

  bool has_error = false;
  std::vector<struct bpf_link *> links;
  std::vector<int> cpus = util::get_online_cpus();
  for (int cpu : cpus) {
    int perf_event_fd = open_perf_event(PERF_TYPE_HARDWARE,
                                        type,
                                        period,
                                        0,
                                        pid.has_value() ? *pid : -1,
                                        cpu,
                                        group_fd);

    if (perf_event_fd < 0) {
      has_error = true;
      break;
    }

    auto *link = bpf_program__attach_perf_event(prog.bpf_prog(), perf_event_fd);
    if (!link) {
      close(perf_event_fd);
      has_error = true;
      break;
    }

    links.push_back(link);
  }

  if (has_error) {
    for (struct bpf_link *link : links) {
      if (bpf_link__destroy(link))
        LOG(WARNING) << "failed to destroy link for hardware probe: "
                     << strerror(errno);
    }
    return make_error<AttachError>();
  }

  return std::unique_ptr<AttachedHardwareProbe>(
      new AttachedHardwareProbe(probe, links));
}

class AttachedFentryProbe : public AttachedProbe {
public:
  static Result<std::unique_ptr<AttachedFentryProbe>> make(
      Probe &probe,
      const BpfProgram &prog);
  ~AttachedFentryProbe() override;

private:
  AttachedFentryProbe(const Probe &probe, int tracing_fd);
  int tracing_fd_;
};

AttachedFentryProbe::AttachedFentryProbe(const Probe &probe, int tracing_fd)
    : AttachedProbe(probe), tracing_fd_(tracing_fd)
{
}

AttachedFentryProbe::~AttachedFentryProbe()
{
  close(tracing_fd_);
}

Result<std::unique_ptr<AttachedFentryProbe>> AttachedFentryProbe::make(
    Probe &probe,
    const BpfProgram &prog)
{
  int tracing_fd = bpf_raw_tracepoint_open(nullptr, prog.fd());
  if (tracing_fd < 0) {
    return make_error<AttachError>();
  }

  return std::unique_ptr<AttachedFentryProbe>(
      new AttachedFentryProbe(probe, tracing_fd));
}

class AttachedRawtracepointProbe : public AttachedProbe {
public:
  static Result<std::unique_ptr<AttachedRawtracepointProbe>> make(
      Probe &probe,
      const BpfProgram &prog);
  ~AttachedRawtracepointProbe() override;

private:
  AttachedRawtracepointProbe(const Probe &probe, int tracing_fd);
  int tracing_fd_;
};

AttachedRawtracepointProbe::AttachedRawtracepointProbe(const Probe &probe,
                                                       int tracing_fd)
    : AttachedProbe(probe), tracing_fd_(tracing_fd)
{
}

AttachedRawtracepointProbe::~AttachedRawtracepointProbe()
{
  close(tracing_fd_);
}

Result<std::unique_ptr<AttachedRawtracepointProbe>> AttachedRawtracepointProbe::
    make(Probe &probe, const BpfProgram &prog)
{
  int tracing_fd = bpf_raw_tracepoint_open(nullptr, prog.fd());
  if (tracing_fd < 0) {
    if (tracing_fd == -ENOENT) {
      return make_error<AttachError>("Probe does not exist: " + probe.name);
    } else if (tracing_fd == -EINVAL) {
      return make_error<AttachError>(
          "Maybe trying to access arguments beyond what's available in "
          "this tracepoint");
    }
    return make_error<AttachError>();
  }

  return std::unique_ptr<AttachedRawtracepointProbe>(
      new AttachedRawtracepointProbe(probe, tracing_fd));
}

class AttachedIterProbe : public AttachedProbe {
public:
  static Result<std::unique_ptr<AttachedIterProbe>> make(
      Probe &probe,
      const BpfProgram &prog,
      std::optional<int> pid);
  ~AttachedIterProbe() override;

  int link_fd() override;

private:
  AttachedIterProbe(const Probe &probe, int iter_link_fd);
  const int iter_link_fd_;
};

AttachedIterProbe::AttachedIterProbe(const Probe &probe, int iter_link_fd)
    : AttachedProbe(probe), iter_link_fd_(iter_link_fd)
{
}

AttachedIterProbe::~AttachedIterProbe()
{
  close(iter_link_fd_);
}

Result<std::unique_ptr<AttachedIterProbe>> AttachedIterProbe::make(
    Probe &probe,
    const BpfProgram &prog,
    std::optional<int> pid)
{
  int iter_fd = -1;
  if (!pid.has_value()) {
    iter_fd = bpf_link_create(prog.fd(), 0, BPF_TRACE_ITER, nullptr);
  } else {
    DECLARE_LIBBPF_OPTS(bpf_link_create_opts, opts);
    union bpf_iter_link_info linfo;
    memset(&linfo, 0, sizeof(linfo));
    linfo.task.pid = *pid;
    opts.iter_info = &linfo;
    opts.iter_info_len = sizeof(linfo);
    iter_fd = bpf_link_create(prog.fd(), 0, BPF_TRACE_ITER, &opts);
  }

  if (iter_fd < 0) {
    return make_error<AttachError>();
  }

  return std::unique_ptr<AttachedIterProbe>(
      new AttachedIterProbe(probe, iter_fd));
}

int AttachedIterProbe::link_fd()
{
  return iter_link_fd_;
}

class AttachedWatchpointProbe : public AttachedProbe {
public:
  static Result<std::unique_ptr<AttachedWatchpointProbe>> make(
      Probe &probe,
      const BpfProgram &prog,
      std::optional<int> pid,
      const std::string &mode);
  ~AttachedWatchpointProbe() override;

private:
  AttachedWatchpointProbe(const Probe &probe,
                          std::vector<struct bpf_link *> links);
  std::vector<struct bpf_link *> links_;
};

AttachedWatchpointProbe::AttachedWatchpointProbe(
    const Probe &probe,
    std::vector<struct bpf_link *> links)
    : AttachedProbe(probe), links_(std::move(links))
{
}

AttachedWatchpointProbe::~AttachedWatchpointProbe()
{
  for (struct bpf_link *link : links_) {
    if (bpf_link__destroy(link))
      LOG(WARNING) << "failed to destroy link for watchpoint probe: "
                   << strerror(errno);
  }
}

Result<std::unique_ptr<AttachedWatchpointProbe>> AttachedWatchpointProbe::make(
    Probe &probe,
    const BpfProgram &prog,
    std::optional<int> pid,
    const std::string &mode)
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

  attr.bp_addr = probe.address;
  // https://man7.org/linux/man-pages/man2/perf_event_open.2.html
  attr.bp_len = (attr.bp_type & HW_BREAKPOINT_X) ? sizeof(long) : probe.len;
  // Generate a notification every 1 event; we care about every event
  attr.sample_period = 1;
  // Attach to threads.
  //
  // NB: this only works for threads created after attachment
  // (limitation of perf_event_open)!
  attr.inherit = 1;

  std::vector<int> cpus;
  if (pid.has_value()) {
    cpus = { -1 };
  } else {
    cpus = util::get_online_cpus();
  }

  std::string err_msg;
  bool has_error = false;
  std::vector<struct bpf_link *> links;

  for (int cpu : cpus) {
    // We copy paste the code from bcc's bpf_attach_perf_event_raw here
    // because we need to know the exact error codes (and also we don't
    // want bcc's noisy error messages).
    int perf_event_fd = syscall(__NR_perf_event_open,
                                &attr,
                                pid.has_value() ? *pid : -1,
                                cpu,
                                -1,
                                PERF_FLAG_FD_CLOEXEC);
    if (perf_event_fd < 0) {
      if (errno == ENOSPC)
        err_msg = "No more HW registers left";

      has_error = true;
      break;
    }

    auto *link = bpf_program__attach_perf_event(prog.bpf_prog(), perf_event_fd);
    if (!link) {
      has_error = true;
      break;
    }

    links.push_back(link);
  }

  if (has_error) {
    for (struct bpf_link *link : links) {
      if (bpf_link__destroy(link))
        LOG(WARNING) << "failed to destroy link for watchpoint probe: "
                     << strerror(errno);
    }
    return make_error<AttachError>(std::move(err_msg));
  }

  return std::unique_ptr<AttachedWatchpointProbe>(
      new AttachedWatchpointProbe(probe, links));
}

AttachedProbe::AttachedProbe(const Probe &probe) : probe_(probe)
{
}

Result<std::unique_ptr<AttachedProbe>> AttachedProbe::make(
    Probe &probe,
    const BpfProgram &prog,
    std::optional<int> pid,
    bool safe_mode)
{
  LOG(V1) << "Trying to attach probe: " << probe.name;
  switch (probe.type) {
    case ProbeType::kprobe:
    case ProbeType::kretprobe:
      if (!probe.funcs.empty()) {
        return AttachedMultiKprobeProbe::make(probe, prog);
      }
      return AttachedKprobeProbe::make(probe, prog);
    case ProbeType::tracepoint:
      return AttachedTracepointProbe::make(probe, prog);
    case ProbeType::profile:
      return AttachedProfileProbe::make(probe, prog, pid);
    case ProbeType::interval:
      return AttachedIntervalProbe::make(probe, prog);
    case ProbeType::software:
      return AttachedSoftwareProbe::make(probe, prog, pid);
    case ProbeType::hardware:
      return AttachedHardwareProbe::make(probe, prog, pid);
    case ProbeType::fentry:
    case ProbeType::fexit:
      return AttachedFentryProbe::make(probe, prog);
    case ProbeType::iter:
      return AttachedIterProbe::make(probe, prog, pid);
    case ProbeType::rawtracepoint:
      return AttachedRawtracepointProbe::make(probe, prog);
    case ProbeType::usdt:
      return AttachedUSDTProbe::make(probe, prog, pid);
    case ProbeType::watchpoint:
      return AttachedWatchpointProbe::make(probe, prog, pid, probe.mode);
    case ProbeType::uprobe:
    case ProbeType::uretprobe:
      if (!probe.funcs.empty()) {
        return AttachedMultiUprobeProbe::make(probe, prog, pid);
      }
      return AttachedUprobeProbe::make(probe, prog, pid, safe_mode);
    case ProbeType::invalid:
    case ProbeType::special:
    case ProbeType::test:
    case ProbeType::benchmark: {
      LOG(BUG) << "invalid attached probe type \"" << probe.type << "\"";
    }
  }
  return make_error<AttachError>();
}

} // namespace bpftrace
