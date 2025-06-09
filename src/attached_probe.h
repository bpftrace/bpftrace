#pragma once

#include <cstdint>
#include <string>

#include <bcc/libbpf.h>

#include "bpfprogram.h"
#include "probe_types.h"
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

class LinkQueryError : public ErrorInfo<LinkQueryError> {
public:
  LinkQueryError(int err) : errno_(err) {};
  LinkQueryError() = default;
  static char ID;
  void log(llvm::raw_ostream &OS) const override
  {
    OS << std::strerror(errno_);
  }

private:
  int errno_ = 0;
};

class AttachedProbe {
public:
  static Result<std::unique_ptr<AttachedProbe>> make(Probe &probe,
                                                     const BpfProgram &prog,
                                                     std::optional<int> pid,
                                                     BPFtrace &bpftrace,
                                                     bool safe_mode = true);
  virtual ~AttachedProbe() = default;
  AttachedProbe(const AttachedProbe &) = delete;
  AttachedProbe &operator=(const AttachedProbe &) = delete;

  // Returns FD for underlying BPF link, if any.
  virtual int link_fd()
  {
    return -1;
  }

  virtual size_t probe_count() const
  {
    return 1;
  }

  // Returns the number of missed executions.
  //
  // NB: the returned value is the number of missed executions since the last
  // time this method was called. IOW: not monotically increasing.
  Result<uint64_t> missed();

  const Probe &probe() const
  {
    return probe_;
  }

protected:
  AttachedProbe(const Probe &probe);
  const Probe &probe_;

private:
  uint64_t last_missed_ = 0;
};

} // namespace bpftrace
