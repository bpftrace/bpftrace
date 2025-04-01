#pragma once

#include <bcc/libbpf.h>
#include <functional>
#include <string>
#include <vector>

#include "bpffeature.h"
#include "bpfprogram.h"
#include "btf.h"
#include "probe_types.h"
#include "usdt.h"

namespace bpftrace {

bpf_probe_attach_type attachtype(ProbeType t);
libbpf::bpf_prog_type progtype(ProbeType t);
std::string progtypeName(libbpf::bpf_prog_type t);

class AttachedProbe {
public:
  AttachedProbe(Probe &probe,
                const BpfProgram &prog,
                std::optional<int> pid,
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
  void resolve_offset_kprobe();
  bool resolve_offset_uprobe(bool safe_mode, bool has_multiple_aps);
  void attach_multi_kprobe();
  void attach_multi_uprobe(std::optional<int> pid);
  void attach_kprobe();
  void attach_uprobe(std::optional<int> pid, bool safe_mode);

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
  void attach_usdt(std::optional<int> pid, BPFfeature &feature);

  void attach_tracepoint();
  void attach_profile(std::optional<int> pid);
  void attach_interval(std::optional<int> pid);
  void attach_software(std::optional<int> pid);
  void attach_hardware(std::optional<int> pid);
  void attach_watchpoint(std::optional<int> pid, const std::string &mode);
  void attach_fentry();
  int detach_fentry();
  void attach_iter(std::optional<int> pid);
  int detach_iter();
  void attach_raw_tracepoint();
  int detach_raw_tracepoint();

  static std::map<std::string, int> cached_prog_fds_;
  bool use_cached_progfd(BPFfeature &feature);
  void cache_progfd();

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
