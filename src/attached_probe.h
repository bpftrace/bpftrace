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
#include "util/result.h"

namespace bpftrace {

bpf_probe_attach_type attachtype(ProbeType t);
libbpf::bpf_prog_type progtype(ProbeType t);
std::string progtypeName(libbpf::bpf_prog_type t);

class AttachError : public ErrorInfo<AttachError> {
public:
  AttachError(std::string &&msg) : msg_(std::move(msg)) {};
  AttachError() = default;
  static char ID;
  void log(llvm::raw_ostream &OS) const override;
  const std::string &msg() const
  {
    return msg_;
  }

private:
  std::string msg_;
};

class AttachedProbe {
public:
  static Result<std::unique_ptr<AttachedProbe>> make(Probe &probe,
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
  AttachedProbe(Probe &probe,
                const BpfProgram &prog,
                std::optional<int> pid,
                BPFtrace &bpftrace,
                bool safe_mode);
  Result<> attach();
  std::string eventprefix() const;
  std::string eventname() const;
  Result<uint64_t> resolve_offset(const std::string &path,
                                  const std::string &symbol,
                                  uint64_t loc);
  Result<> resolve_offset_kprobe();
  Result<> resolve_offset_uprobe(bool safe_mode);
  Result<> resolve_offset_uprobe_multi(const std::string &path,
                                       const std::string &probe_name,
                                       const std::vector<std::string> &funcs,
                                       std::vector<std::string> &syms,
                                       std::vector<unsigned long> &offsets);
  Result<> attach_multi_kprobe();
  Result<> attach_multi_uprobe();
  Result<> attach_kprobe();
  Result<> attach_uprobe(bool safe_mode);

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
  Result<> attach_usdt(BPFfeature &feature);

  Result<> attach_tracepoint();
  Result<> attach_profile();
  Result<> attach_interval();
  Result<> attach_software();
  Result<> attach_hardware();
  Result<> attach_watchpoint(const std::string &mode);
  Result<> attach_fentry();
  int detach_fentry();
  Result<> attach_iter();
  int detach_iter();
  Result<> attach_raw_tracepoint();
  int detach_raw_tracepoint();

  static std::map<std::string, int> cached_prog_fds_;
  bool use_cached_progfd(BPFfeature &feature);
  void cache_progfd();
  Result<> check_alignment(std::string &path,
                           std::string &symbol,
                           uint64_t sym_offset,
                           uint64_t func_offset,
                           bool safe_mode,
                           ProbeType type);

  Probe &probe_;
  std::vector<int> perf_event_fds_;
  bool close_progfd_ = true;
  int progfd_ = -1;
  uint64_t offset_ = 0;
  int tracing_fd_ = -1;
  std::function<void()> usdt_destructor_;
  USDTHelper usdt_helper;

  BPFtrace &bpftrace_;
  std::optional<int> pid_;
  bool safe_mode_;
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
