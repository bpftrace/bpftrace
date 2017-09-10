#pragma once

#include "types.h"

#include "libbpf.h"

namespace bpftrace {

bpf_probe_attach_type attachtype(ProbeType t);
bpf_prog_type progtype(ProbeType t);

class AttachedProbe
{
public:
  AttachedProbe(Probe &probe, std::tuple<uint8_t *, uintptr_t> &func);
  ~AttachedProbe();
  AttachedProbe(const AttachedProbe &) = delete;
  AttachedProbe& operator=(const AttachedProbe &) = delete;

private:
  std::string eventprefix() const;
  std::string eventname() const;
  static std::string sanitise(const std::string &str);
  uint64_t offset() const;
  void load_prog();
  void attach_kprobe();
  void attach_uprobe();
  void attach_tracepoint();
  void attach_profile();
  int detach_profile();

  Probe &probe_;
  std::tuple<uint8_t *, uintptr_t> &func_;
  std::vector<int> perf_event_fds_;
  void *perf_reader_ = nullptr;
  int progfd_;
};

} // namespace bpftrace
