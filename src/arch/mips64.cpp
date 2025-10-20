#include <unordered_map>

#include "arch.h"

namespace bpftrace::arch {

template <>
std::string Arch<Machine::MIPS64>::asm_arch()
{
  return "mips";
}

template <>
size_t Arch<Machine::MIPS64>::kernel_ptr_width()
{
  return 64;
}

template <>
const std::vector<std::string>& Arch<Machine::MIPS64>::c_defs()
{
  static std::vector<std::string> defs = {
    "__TARGET_ARCH_mips",
  };
  return defs;
}

template <>
const std::unordered_set<std::string>& Arch<Machine::MIPS64>::watchpoint_modes()
{
  static std::unordered_set<std::string> valid_modes = {};
  return valid_modes;
}

} // namespace bpftrace::arch
