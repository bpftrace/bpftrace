#include <unordered_map>

#include "arch.h"

namespace bpftrace::arch {

template <>
std::string Arch<Machine::X86_64>::asm_arch()
{
  return "x86";
}

template <>
size_t Arch<Machine::X86_64>::kernel_ptr_width()
{
  return 64;
}

template <>
const std::vector<std::string>& Arch<Machine::X86_64>::c_defs()
{
  static std::vector<std::string> defs = {
    "__TARGET_ARCH_x86",
  };
  return defs;
}

template <>
const std::unordered_set<std::string>& Arch<X86_64>::watchpoint_modes()
{
  // See intel developer manual, Volume 3, section 17.2.4.
  static std::unordered_set<std::string> valid_modes = {
    "rw",
    "w",
    "x",
  };
  return valid_modes;
}

} // namespace bpftrace::arch
