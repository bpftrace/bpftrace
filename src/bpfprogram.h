#pragma once

#include <cstdint>
#include <cstring>

#include <bpf/libbpf.h>

#include "bpffeature.h"
#include "btf.h"
#include "config.h"
#include "probe_types.h"
#include "util/result.h"

namespace bpftrace {

class ProgramQueryError : public ErrorInfo<ProgramQueryError> {
public:
  ProgramQueryError(int err) : errno_(err) {};
  ProgramQueryError() = default;
  static char ID;
  void log(llvm::raw_ostream &OS) const override
  {
    OS << std::strerror(errno_);
  }

private:
  int errno_ = 0;
};

class BpfBytecode;
class BPFtrace;

// This class abstracts a single BPF program by encapsulating libbpf's
// 'struct bpf_prog'.
class BpfProgram {
public:
  explicit BpfProgram(struct bpf_program *bpf_prog);

  void set_prog_type(const Probe &probe);
  void set_expected_attach_type(const Probe &probe, BPFfeature &feature);
  void set_attach_target(const Probe &probe,
                         const BTF &btf,
                         const Config &config);
  void set_no_autoattach();

  int fd() const;
  struct bpf_program *bpf_prog() const;

  // Returns the number of missed executions due to recursion prevention.
  //
  // NB: the returned value is the number of missed executions since the last
  // time this method was called. IOW: not monotically increasing.
  Result<uint64_t> missed();

  BpfProgram(const BpfProgram &) = delete;
  BpfProgram &operator=(const BpfProgram &) = delete;
  BpfProgram(BpfProgram &&) = default;
  BpfProgram &operator=(BpfProgram &&) = default;

private:
  struct bpf_program *bpf_prog_;
  uint64_t last_missed_ = 0;
};

} // namespace bpftrace
