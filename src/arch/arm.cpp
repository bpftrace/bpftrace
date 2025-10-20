#include <unordered_map>

#include "arch.h"

namespace bpftrace::arch {

template <>
std::string Arch<Machine::ARM>::asm_arch()
{
  return "arm";
}

template <>
size_t Arch<Machine::ARM>::kernel_ptr_width()
{
  return 32;
}

template <>
const std::vector<std::string>& Arch<Machine::ARM>::c_defs()
{
  static std::vector<std::string> defs = {
    "__TARGET_ARCH_arm",
  };
  return defs;
}

template <>
const std::unordered_set<std::string>& Arch<Machine::ARM>::watchpoint_modes()
{
  // See arch/arm/kernel/hw_breakpoint.c:arch_build_bp_info in kernel source.
  static std::unordered_set<std::string> valid_modes = {
    "r",
    "w",
    "x",
    "rw",
  };
  return valid_modes;
}

template <>
std::string Arch<Machine::ARM64>::asm_arch()
{
  return "arm64";
}

template <>
size_t Arch<Machine::ARM64>::kernel_ptr_width()
{
  return 64;
}

template <>
const std::vector<std::string>& Arch<Machine::ARM64>::c_defs()
{
  static std::vector<std::string> defs = {
    "__TARGET_ARCH_arm64",
  };
  return defs;
}

template <>
const std::unordered_set<std::string>& Arch<Machine::ARM64>::watchpoint_modes()
{
  // See arch/arm/kernel/hw_breakpoint.c:arch_build_bp_info in kernel source.
  static std::unordered_set<std::string> valid_modes = {
    "r",
    "w",
    "x",
    "rw",
  };
  return valid_modes;
}

} // namespace bpftrace::arch
