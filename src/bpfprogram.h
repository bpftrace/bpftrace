#pragma once

#include "bpffeature.h"
#include "btf.h"
#include "config.h"
#include "types.h"

#include <bpf/libbpf.h>

namespace bpftrace {

class BpfBytecode;
class BPFtrace;

// This class abstracts a single BPF program by encapsulating libbpf's
// 'struct bpf_prog'.
class BpfProgram {
public:
  explicit BpfProgram(struct bpf_program *bpf_prog);

  void set_prog_type(const Probe &probe, BPFfeature &feature);
  void set_expected_attach_type(const Probe &probe, BPFfeature &feature);
  void set_attach_target(const Probe &probe,
                         const BTF &btf,
                         const Config &config);
  void set_no_autoattach();

  int fd() const;
  struct bpf_program *bpf_prog() const;

  BpfProgram(const BpfProgram &) = delete;
  BpfProgram &operator=(const BpfProgram &) = delete;
  BpfProgram(BpfProgram &&) = default;
  BpfProgram &operator=(BpfProgram &&) = default;

private:
  struct bpf_program *bpf_prog_;
};

} // namespace bpftrace
