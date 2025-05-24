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
  virtual ~AttachedProbe();
  AttachedProbe(const AttachedProbe &) = delete;
  AttachedProbe &operator=(const AttachedProbe &) = delete;

  virtual int get_link_fd();

  const Probe &probe() const
  {
    return probe_;
  }

protected:
  AttachedProbe(const Probe &probe, int progfd);

private:
  const Probe &probe_;
  const int progfd_;
};

class AttachedKprobeProbe : public AttachedProbe {
public:
  static Result<std::unique_ptr<AttachedKprobeProbe>> make(
      Probe &probe,
      const BpfProgram &prog,
      BPFtrace &bpftrace);
  ~AttachedKprobeProbe() override;

private:
  AttachedKprobeProbe(const Probe &probe,
                      int progfd,
                      int perf_event_fd,
                      std::string event_name);
  int perf_event_fd_;
  const std::string event_name_;
};

class AttachedMultiKprobeProbe : public AttachedProbe {
public:
  static Result<std::unique_ptr<AttachedMultiKprobeProbe>> make(
      Probe &probe,
      const BpfProgram &prog);
  ~AttachedMultiKprobeProbe() override;

private:
  AttachedMultiKprobeProbe(const Probe &probe, int progfd, int link_fd);
  int link_fd_;
};

class AttachedUprobeProbe : public AttachedProbe {
public:
  static Result<std::unique_ptr<AttachedUprobeProbe>> make(
      Probe &probe,
      const BpfProgram &prog,
      std::optional<int> pid,
      bool safe_mode);
  ~AttachedUprobeProbe() override;

private:
  AttachedUprobeProbe(const Probe &probe,
                      int progfd,
                      int perf_event_fd,
                      std::string event_name);
  int perf_event_fd_;
  const std::string event_name_;
};

class AttachedMultiUprobeProbe : public AttachedProbe {
public:
  static Result<std::unique_ptr<AttachedMultiUprobeProbe>> make(
      Probe &probe,
      const BpfProgram &prog,
      std::optional<int> pid);
  ~AttachedMultiUprobeProbe() override;

private:
  AttachedMultiUprobeProbe(const Probe &probe, int progfd, int link_fd);
  int link_fd_;
};

class AttachedUSDTProbe : public AttachedProbe {
public:
  static Result<std::unique_ptr<AttachedUSDTProbe>> make(Probe &probe,
                                                         const BpfProgram &prog,
                                                         std::optional<int> pid,
                                                         BPFfeature &feature);
  ~AttachedUSDTProbe() override;

private:
  AttachedUSDTProbe(const Probe &probe,
                    int progfd,
                    int perf_event_fd,
                    std::function<void()> cleanup);
  int perf_event_fd_;
  std::function<void()> usdt_sem_cleanup_;
};

class AttachedTracepointProbe : public AttachedProbe {
public:
  static Result<std::unique_ptr<AttachedTracepointProbe>> make(
      Probe &probe,
      const BpfProgram &prog);
  ~AttachedTracepointProbe() override;

private:
  AttachedTracepointProbe(const Probe &probe,
                          int progfd,
                          int perf_event_fd,
                          std::string event_name,
                          std::string probe_path);
  int perf_event_fd_;
  const std::string event_name_;
  const std::string probe_path_;
};

class AttachedProfileProbe : public AttachedProbe {
public:
  static Result<std::unique_ptr<AttachedProfileProbe>> make(
      Probe &probe,
      const BpfProgram &prog,
      std::optional<int> pid);
  ~AttachedProfileProbe() override;

private:
  AttachedProfileProbe(const Probe &probe,
                       int progfd,
                       std::vector<int> perf_event_fds);
  std::vector<int> perf_event_fds_;
};

class AttachedIntervalProbe : public AttachedProbe {
public:
  static Result<std::unique_ptr<AttachedIntervalProbe>> make(
      Probe &probe,
      const BpfProgram &prog,
      std::optional<int> pid);
  ~AttachedIntervalProbe() override;

private:
  AttachedIntervalProbe(const Probe &probe, int progfd, int perf_event_fd);
  int perf_event_fd_;
};

class AttachedSoftwareProbe : public AttachedProbe {
public:
  static Result<std::unique_ptr<AttachedSoftwareProbe>> make(
      Probe &probe,
      const BpfProgram &prog,
      std::optional<int> pid);
  ~AttachedSoftwareProbe() override;

private:
  AttachedSoftwareProbe(const Probe &probe,
                        int progfd,
                        std::vector<int> perf_event_fds);
  std::vector<int> perf_event_fds_;
};

class AttachedHardwareProbe : public AttachedProbe {
public:
  static Result<std::unique_ptr<AttachedHardwareProbe>> make(
      Probe &probe,
      const BpfProgram &prog,
      std::optional<int> pid);
  ~AttachedHardwareProbe() override;

private:
  AttachedHardwareProbe(const Probe &probe,
                        int progfd,
                        std::vector<int> perf_event_fds);
  std::vector<int> perf_event_fds_;
};

class AttachedFentryProbe : public AttachedProbe {
public:
  static Result<std::unique_ptr<AttachedFentryProbe>> make(
      Probe &probe,
      const BpfProgram &prog);
  ~AttachedFentryProbe() override;

private:
  AttachedFentryProbe(const Probe &probe, int progfd, int tracing_fd);
  int tracing_fd_;
};

class AttachedRawtracepointProbe : public AttachedProbe {
public:
  static Result<std::unique_ptr<AttachedRawtracepointProbe>> make(
      Probe &probe,
      const BpfProgram &prog);
  ~AttachedRawtracepointProbe() override;

private:
  AttachedRawtracepointProbe(const Probe &probe, int progfd, int tracing_fd);
  int tracing_fd_;
};

class AttachedIterProbe : public AttachedProbe {
public:
  static Result<std::unique_ptr<AttachedIterProbe>> make(
      Probe &probe,
      const BpfProgram &prog,
      std::optional<int> pid);
  ~AttachedIterProbe() override;

  int get_link_fd() override;

private:
  AttachedIterProbe(const Probe &probe, int progfd, int iter_link_fd);
  const int iter_link_fd_;
};

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
                          int progfd,
                          std::vector<int> perf_event_fds);
  std::vector<int> perf_event_fds_;
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
