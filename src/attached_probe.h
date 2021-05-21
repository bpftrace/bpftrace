#pragma once

#include <functional>
#include <string>
#include <tuple>
#include <vector>

#include "bpffeature.h"
#include "types.h"

#include <bcc/libbpf.h>

namespace bpftrace {

bpf_probe_attach_type attachtype(ProbeType t);
bpf_prog_type progtype(ProbeType t);
std::string progtypeName(bpf_prog_type t);

class AttachedProbe
{
public:
  AttachedProbe(Probe &probe,
                std::tuple<uint8_t *, uintptr_t> func,
                bool safe_mode);
  AttachedProbe(Probe &probe,
                std::tuple<uint8_t *, uintptr_t> func,
                int pid,
                BPFfeature &feature);
  ~AttachedProbe();
  AttachedProbe(const AttachedProbe &) = delete;
  AttachedProbe &operator=(const AttachedProbe &) = delete;

  const Probe &probe() const;
  int linkfd_ = -1;

private:
  std::string eventprefix() const;
  std::string eventname() const;
  static std::string sanitise(const std::string &str);
  void resolve_offset_kprobe(bool safe_mode);
  void resolve_offset_uprobe(bool safe_mode);
  void load_prog();
  void attach_kprobe(bool safe_mode);
  void attach_uprobe(bool safe_mode);

  // Note: the following usdt attachment functions will only activate a
  // semaphore if one exists.
  //
  // Increment semaphore count manually with memory hogging API (least
  // preferrable)
  int usdt_sem_up_manual(const std::string &fn_name, void *ctx);
  // Increment semaphore count manually with BCC addsem API
  int usdt_sem_up_manual_addsem(int pid, const std::string &fn_name, void *ctx);
  int usdt_sem_up(BPFfeature &feature,
                  int pid,
                  const std::string &fn_name,
                  void *ctx);
  void attach_usdt(int pid, BPFfeature &feature);

  void attach_tracepoint();
  void attach_profile();
  void attach_interval();
  void attach_software();
  void attach_hardware();
  void attach_watchpoint(int pid, const std::string &mode);
  void attach_kfunc(void);
  int detach_kfunc(void);
  void attach_iter(void);
  int detach_iter(void);

  Probe &probe_;
  std::tuple<uint8_t *, uintptr_t> func_;
  std::vector<int> perf_event_fds_;
  int progfd_ = -1;
  uint64_t offset_ = 0;
  int tracing_fd_ = -1;
  std::function<void()> usdt_destructor_;
};

} // namespace bpftrace
