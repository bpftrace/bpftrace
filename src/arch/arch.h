#pragma once

#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

namespace bpftrace::arch {

// Canonical enum for different architectures.
enum Machine {
  X86_64,
  ARM,
  ARM64,
  S390X,
  PPC64,
  MIPS64,
  RISCV64,
  LOONGARCH64,
};

// Allow printing of the machine type.
std::ostream& operator<<(std::ostream& out, Machine m);

// In order to ensure that all architecture sources are always compiled, we
// define the architecture details as a specific instance of the various
// architecture classes. Unused architectures should be stripped out at link
// time as those functions are unreferenced.
template <Machine M>
class Arch {
public:
  constexpr static auto Machine = M;

  // Returns the assembly name for the architecture.
  static std::string asm_arch();

  // Returns the width of bits in kernel pointers.
  static size_t kernel_ptr_width();

  // Returns additional C definitions that should be applied to compiled code.
  static const std::vector<std::string>& c_defs();

  // Returns the set of valid watchpoint modes.
  static const std::unordered_set<std::string>& watchpoint_modes();
};

// Returns the `Machine` for the compiled architecture.
constexpr Machine current()
{
#if defined(__x86_64__) || defined(__amd64__)
  return Machine::X86_64;
#elif defined(__aarch64__)
  return Machine::ARM64;
#elif defined(__arm__)
  return Machine::ARM;
#elif defined(__s390x__)
  return Machine::S390X;
#elif defined(__ppc64__) || defined(__powerpc64__)
  return Machine::PPC64;
#elif defined(__mips64)
  return Machine::MIPS64;
#elif defined(__riscv) && (__riscv_xlen == 64)
  return Machine::RISCV64;
#elif defined(__loongarch64)
  return Machine::LOONGARCH64;
#else
#error "Unknown architecture."
#endif
}

// Alias for the current host architecture.
using Host = Arch<current()>;

} // namespace bpftrace::arch
