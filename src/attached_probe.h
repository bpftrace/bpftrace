#pragma once

#include <functional>
#include <string>
#include <vector>

#include "bpffeature.h"
#include "bpfprogram.h"
#include "btf.h"
#include "probe_types.h"
#include "util/result.h"

namespace bpftrace {

bool is_return_type(ProbeType t);
bpf_prog_type progtype(ProbeType t);
std::string progtypeName(bpf_prog_type t);

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
                                                     bool safe_mode = true);
  virtual ~AttachedProbe() = default;
  AttachedProbe(const AttachedProbe &) = delete;
  AttachedProbe &operator=(const AttachedProbe &) = delete;

  virtual int link_fd()
  {
    return -1;
  }

  virtual size_t probe_count() const
  {
    return 1;
  }

  const Probe &probe() const
  {
    return probe_;
  }

protected:
  AttachedProbe(const Probe &probe);
  const Probe &probe_;
};

} // namespace bpftrace
