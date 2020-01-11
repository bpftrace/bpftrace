#pragma once

#include "types.h"

#include "libbpf.h"

namespace bpftrace {

bpf_probe_attach_type attachtype(ProbeType t);
bpf_prog_type progtype(ProbeType t);

class AttachedProbe
{
public:
  AttachedProbe(Probe &probe,
                std::tuple<uint8_t *, uintptr_t> func,
                bool safe_mode);
  AttachedProbe(Probe &probe, std::tuple<uint8_t *, uintptr_t> func, int pid);
  ~AttachedProbe();
  AttachedProbe(const AttachedProbe &) = delete;
  AttachedProbe &operator=(const AttachedProbe &) = delete;

private:
  std::string eventprefix() const;
  std::string eventname() const;
  static std::string sanitise(const std::string &str);
  void resolve_offset_kprobe(bool safe_mode);
  void resolve_offset_uprobe(bool safe_mode);
  void load_prog();
  void attach_kprobe(bool safe_mode);
  void attach_uprobe(bool safe_mode);
  void attach_usdt(int pid);
  void attach_tracepoint();
  void attach_profile();
  void attach_interval();
  void attach_software();
  void attach_hardware();
  void attach_watchpoint(int pid, const std::string &mode);

  Probe &probe_;
  std::tuple<uint8_t *, uintptr_t> func_;
  std::vector<int> perf_event_fds_;
  int progfd_ = -1;
  uint64_t offset_ = 0;
};

} // namespace bpftrace
