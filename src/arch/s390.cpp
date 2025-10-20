#include <unordered_map>

#include "arch.h"

namespace bpftrace::arch {

template <>
std::string Arch<Machine::S390X>::asm_arch()
{
  return "s390";
}

template <>
size_t Arch<Machine::S390X>::kernel_ptr_width()
{
  return 64;
}

template <>
const std::vector<std::string>& Arch<Machine::S390X>::c_defs()
{
  static std::vector<std::string> defs = {
    "__TARGET_ARCH_s390",
  };
  return defs;
}

template <>
const std::unordered_set<std::string>& Arch<Machine::S390X>::watchpoint_modes()
{
  static std::unordered_set<std::string> valid_modes = {};
  return valid_modes;
}

} // namespace bpftrace::arch
