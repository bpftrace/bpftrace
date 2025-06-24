#include <unordered_map>

#include "arch.h"

namespace bpftrace::arch {

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
std::optional<size_t> Arch<Machine::X86_64>::register_to_pt_regs_offset(
    const std::string& name)
{
  static const std::unordered_map<std::string, size_t> register_offsets = {
    { "r15", 0 },  { "r14", 8 },  { "r13", 16 },    { "r12", 24 },
    { "bp", 32 },  { "bx", 40 },  { "r11", 48 },    { "r10", 56 },
    { "r9", 64 },  { "r8", 72 },  { "ax", 80 },     { "cx", 88 },
    { "dx", 96 },  { "si", 104 }, { "di", 112 },    { "orig_rax", 120 },
    { "ip", 128 }, { "cs", 136 }, { "flags", 144 }, { "sp", 152 },
    { "ss", 160 },
  };
  auto it = register_offsets.find(name);
  if (it != register_offsets.end()) {
    return it->second;
  }
  return std::nullopt;
}

template <>
std::optional<std::string> Arch<Machine::X86_64>::register_to_pt_regs_expr(
    const std::string& name)
{
  // All the registers in x86-64 are defined against the existing pt_regs
  // struct, and there are no aliases. In the future, we could define aliases
  // like the `rXX` variants as opposed to `ax`, `bx`, etc. or we could add
  // aliases like `fp` for `bp`.
  auto offset = register_to_pt_regs_offset(name);
  if (!offset) {
    return std::nullopt;
  }
  return name;
}

template <>
const std::vector<std::string>& Arch<Machine::X86_64>::arguments()
{
  static std::vector<std::string> args = {
    "di", "si", "dx", "cx", "r8", "r9",
  };
  return args;
}

template <>
size_t Arch<Machine::X86_64>::argument_stack_offset()
{
  // The return address is pushed on the frame, so we need to reach up
  // the stack further to find the first argument.
  return 8;
}

template <>
std::string Arch<Machine::X86_64>::return_value()
{
  return "ax";
}

template <>
std::string Arch<Machine::X86_64>::pc_value()
{
  return "ip";
}

template <>
std::string Arch<Machine::X86_64>::sp_value()
{
  return "sp";
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
