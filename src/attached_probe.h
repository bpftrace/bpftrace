#pragma once

#include <functional>
#include <string>
#include <tuple>
#include <vector>

#include "bpffeature.h"
#include "bpfprogram.h"
#include "btf.h"
#include "types.h"

#include <bcc/libbpf.h>

namespace bpftrace {

bpf_probe_attach_type attachtype(ProbeType t);
libbpf::bpf_prog_type progtype(ProbeType t);
std::string progtypeName(libbpf::bpf_prog_type t);

class AttachedProbe
{
public:
  AttachedProbe(Probe &probe,
                BpfProgram &&prog,
                bool safe_mode,
                BPFfeature &feature,
                BTF &btf);
  AttachedProbe(Probe &probe,
                BpfProgram &&prog,
                int pid,
                BPFfeature &feature,
                BTF &btf);
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
  bool resolve_offset_uprobe(bool safe_mode);
  void load_prog(BPFfeature &feature);
  void attach_multi_kprobe(void);
  void attach_multi_uprobe(void);
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
  void attach_raw_tracepoint(void);
  int detach_raw_tracepoint(void);

  static std::map<std::string, int> cached_prog_fds_;
  bool use_cached_progfd(void);
  void cache_progfd(void);

  Probe &probe_;
  BpfProgram prog_;
  std::vector<int> perf_event_fds_;
  bool close_progfd_ = true;
  int progfd_ = -1;
  uint64_t offset_ = 0;
  int tracing_fd_ = -1;
  std::function<void()> usdt_destructor_;

  BTF &btf_;
};

class HelperVerifierError : public std::runtime_error
{
public:
  const libbpf::bpf_func_id func_id_;
  const std::string helper_name_;
  explicit HelperVerifierError(libbpf::bpf_func_id func_id,
                               std::string helper_name)
      : std::runtime_error("helper invalid in probe"),
        func_id_(func_id),
        helper_name_(helper_name)
  {
  }
};

} // namespace bpftrace
