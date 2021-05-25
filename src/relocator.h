#pragma once

#include <cstdint>
#include <tuple>

struct bpf_insn;
namespace bpftrace {
class BPFtrace;

// Relocates BPF bytecode prior to being loaded into the kernel
//
// Relocations are needed to customize the bytecode to the host the
// bytecode is going to be run on.
class Relocator
{
public:
  Relocator(std::tuple<uint8_t *, uintptr_t> func, BPFtrace &bpftrace);
  ~Relocator() = default;

  // Perform relocations
  //
  // Note this function will modify the instructions passed into the
  // constructor
  int relocate();

private:
  struct bpf_insn *insns_;
  uintptr_t nr_;
  BPFtrace &bpftrace_;
};

} // namespace bpftrace
