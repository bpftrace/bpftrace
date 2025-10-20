#include <unordered_map>

#include "arch.h"

namespace bpftrace::arch {

template <>
std::string Arch<Machine::PPC64>::asm_arch()
{
  return "powerpc";
}

template <>
size_t Arch<Machine::PPC64>::kernel_ptr_width()
{
  return 64;
}

template <>
const std::vector<std::string>& Arch<Machine::PPC64>::c_defs()
{
  static std::vector<std::string> defs = {
    "__TARGET_ARCH_powerpc",
  };
  return defs;
}

template <>
const std::unordered_set<std::string>& Arch<Machine::PPC64>::watchpoint_modes()
{
  // See PowerISA Book III v3.1B, Section 5.4.4 and 10.4.
  static std::unordered_set<std::string> valid_modes = {
    "r",
    "w",
    "rw",
  };
  return valid_modes;
}

} // namespace bpftrace::arch
