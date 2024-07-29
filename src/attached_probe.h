#pragma once

#include <functional>
#include <string>
#include <tuple>
#include <vector>

#include "bpffeature.h"
#include "bpfprogram.h"
#include "btf.h"
#include "config.h"
#include "types.h"
#include "usdt.h"

#include <bcc/libbpf.h>

namespace bpftrace {

bpf_probe_attach_type attachtype(ProbeType t);
libbpf::bpf_prog_type progtype(ProbeType t);
std::string progtypeName(libbpf::bpf_prog_type t);

class AttachedProbe {
public:
  AttachedProbe(Probe &probe,
                const BpfProgram &prog,
                bool safe_mode,
                BPFtrace &bpftrace);
  AttachedProbe(Probe &probe,
                const BpfProgram &prog,
                int pid,
                BPFtrace &bpftrace,
                bool safe_mode = true);
  ~AttachedProbe();
  AttachedProbe(const AttachedProbe &) = delete;
  AttachedProbe &operator=(const AttachedProbe &) = delete;

  const Probe &probe() const;
  int progfd() const;
  int linkfd_ = -1;

private:
  std::string eventprefix() const;
  std::string eventname() const;
  void resolve_offset_kprobe(bool safe_mode);
  bool resolve_offset_uprobe(bool safe_mode, bool has_multiple_aps);
  void attach_multi_kprobe(void);
  void attach_multi_uprobe(int pid);
  void attach_kprobe(bool safe_mode);
  void attach_uprobe(int pid, bool safe_mode);

  // Note: the following usdt attachment functions will only activate a
  // semaphore if one exists.
  //
  // Increment semaphore count manually with memory hogging API (least
  // preferable)
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
  void attach_raw_tracepoint(void);
  int detach_raw_tracepoint(void);

  static std::map<std::string, int> cached_prog_fds_;
  bool use_cached_progfd(BPFfeature &feature);
  void cache_progfd(void);

  Probe &probe_;
  std::vector<int> perf_event_fds_;
  bool close_progfd_ = true;
  int progfd_ = -1;
  uint64_t offset_ = 0;
  int tracing_fd_ = -1;
  std::function<void()> usdt_destructor_;
  USDTHelper usdt_helper;

  BPFtrace &bpftrace_;
};

class HelperVerifierError : public std::runtime_error {
public:
  HelperVerifierError(const std::string &msg, libbpf::bpf_func_id func_id_)
      : std::runtime_error(msg), func_id(func_id_)
  {
  }

  const libbpf::bpf_func_id func_id;
};

} // namespace bpftrace
