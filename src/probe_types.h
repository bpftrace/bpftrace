#pragma once

#include <cassert>
#include <cereal/access.hpp>
#include <ostream>
#include <string>
#include <sys/types.h>
#include <unistd.h>
#include <unordered_set>
#include <vector>

namespace bpftrace {

enum class ProbeType {
  invalid,
  special,
  kprobe,
  kretprobe,
  uprobe,
  uretprobe,
  usdt,
  tracepoint,
  profile,
  interval,
  software,
  hardware,
  watchpoint,
  asyncwatchpoint,
  fentry,
  fexit,
  iter,
  rawtracepoint,
};

std::ostream &operator<<(std::ostream &os, ProbeType type);

struct ProbeItem {
  std::string name;
  std::unordered_set<std::string> aliases;
  ProbeType type;
  // these are used in bpftrace -l
  // to show which probes are available to attach to
  bool show_in_kernel_list = false;
  bool show_in_userspace_list = false;
};

const std::vector<ProbeItem> PROBE_LIST = {
  { .name = "kprobe",
    .aliases = { "k" },
    .type = ProbeType::kprobe,
    .show_in_kernel_list = true },
  { .name = "kretprobe", .aliases = { "kr" }, .type = ProbeType::kretprobe },
  { .name = "uprobe",
    .aliases = { "u" },
    .type = ProbeType::uprobe,
    .show_in_userspace_list = true },
  { .name = "uretprobe", .aliases = { "ur" }, .type = ProbeType::uretprobe },
  { .name = "usdt",
    .aliases = { "U" },
    .type = ProbeType::usdt,
    .show_in_userspace_list = true },
  { .name = "BEGIN", .aliases = { "BEGIN" }, .type = ProbeType::special },
  { .name = "END", .aliases = { "END" }, .type = ProbeType::special },
  { .name = "self", .aliases = { "self" }, .type = ProbeType::special },
  { .name = "tracepoint",
    .aliases = { "t" },
    .type = ProbeType::tracepoint,
    .show_in_kernel_list = true },
  { .name = "profile", .aliases = { "p" }, .type = ProbeType::profile },
  { .name = "interval", .aliases = { "i" }, .type = ProbeType::interval },
  { .name = "software",
    .aliases = { "s" },
    .type = ProbeType::software,
    .show_in_kernel_list = true },
  { .name = "hardware",
    .aliases = { "h" },
    .type = ProbeType::hardware,
    .show_in_kernel_list = true },
  { .name = "watchpoint", .aliases = { "w" }, .type = ProbeType::watchpoint },
  { .name = "asyncwatchpoint",
    .aliases = { "aw" },
    .type = ProbeType::asyncwatchpoint },
  { .name = "fentry",
    .aliases = { "f", "kfunc" },
    .type = ProbeType::fentry,
    .show_in_kernel_list = true },
  { .name = "fexit",
    .aliases = { "fr", "kretfunc" },
    .type = ProbeType::fexit },
  { .name = "iter",
    .aliases = { "it" },
    .type = ProbeType::iter,
    .show_in_kernel_list = true },
  { .name = "rawtracepoint",
    .aliases = { "rt" },
    .type = ProbeType::rawtracepoint,
    .show_in_kernel_list = true },
};

ProbeType probetype(const std::string &probeName);
std::string expand_probe_name(const std::string &orig_name);
std::string probetypeName(ProbeType t);

struct Probe {
  ProbeType type;
  std::string path;         // file path if used
  std::string attach_point; // probe name (last component)
  std::string orig_name;    // original full probe name,
                            // before wildcard expansion
  std::string name;         // full probe name
  bool need_expansion;
  std::string pin;  // pin file for iterator probes
  std::string ns;   // for USDT probes, if provider namespace not from path
  uint64_t loc = 0; // for USDT probes
  int usdt_location_idx = 0; // to disambiguate duplicate USDT markers
  uint64_t log_size = 1000000;
  int index = 0;
  int freq = 0;
  uint64_t len = 0;   // for watchpoint probes, size of region
  std::string mode;   // for watchpoint probes, watch mode (rwx)
  bool async = false; // for watchpoint probes, if it's an async watchpoint
  uint64_t address = 0;
  uint64_t func_offset = 0;
  std::vector<std::string> funcs;
  bool is_session = false;

private:
  friend class cereal::access;
  template <typename Archive>
  void serialize(Archive &archive)
  {
    archive(type,
            path,
            attach_point,
            orig_name,
            name,
            pin,
            ns,
            loc,
            usdt_location_idx,
            log_size,
            index,
            freq,
            len,
            mode,
            async,
            address,
            func_offset,
            funcs);
  }
};

} // namespace bpftrace
