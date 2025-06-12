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

  // Returns the width of bits in kernel pointers.
  static size_t kernel_ptr_width();

  // Given a conventional register name, return the expression that should be
  // used to access this from `struct pt_regs`. This will be dynamically added
  // and evaluated using the standard type inference mechanisms.
  static std::optional<std::string> register_to_pt_regs_expr(
      const std::string& name);

  // Returns the offset into the context where this register resides.
  //
  // FIXME(#3873): This should be removed in the future. With BTF, there is no
  // need to statically encode the register offsets and we should instead treat
  // these as regular field references into the context (e.g. `ctx.ax`). These
  // field names can then be checked, and will support dynamic reloations, etc.
  // A pass can be added early to transform `regs("r")` into `ctx.r`, and we
  // can have proper type inference and type-checking while throwing out code.
  // However, for now, we retain this method to faciliate the transition.
  static std::optional<size_t> register_to_pt_regs_offset(
      const std::string& name);

  // Returns the canonical sequence of registers used for the default calling
  // convention on this architecture. These should be in the form of fields for
  // `struct pt_regs` (the function above will not be called).
  static const std::vector<std::string>& arguments();

  // Returns the canonical offset into the stack where arguments start to spill.
  static size_t argument_stack_offset();

  // Returns the canonical register used for the return value on this
  // architecture, also in the form of a `struct pt_regs` field.
  static std::string return_value();

  // Returns the canonical register used to store the instruction pointer,
  // also in the form of a `struct pt_regs` field.
  static std::string pc_value();

  // Returns the canonical register used to store the stack pointer, in
  // the form of a `struct pt_regs` fields.
  static std::string sp_value();

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
#elif defined(__ppc64__)
  return Machine::POWERPC;
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
