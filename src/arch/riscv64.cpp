#include <unordered_map>

#include "arch/arch.h"

namespace bpftrace::arch {

template <>
std::string Arch<Machine::RISCV64>::asm_arch()
{
  return "riscv";
}

template <>
size_t Arch<Machine::RISCV64>::kernel_ptr_width()
{
  return 64;
}

template <>
const std::vector<std::string>& Arch<Machine::RISCV64>::c_defs()
{
  static std::vector<std::string> defs = {
    "__TARGET_ARCH_riscv",
  };
  return defs;
}

template <>
std::optional<std::string> Arch<Machine::RISCV64>::register_to_pt_regs_expr(
    const std::string& name)
{
  static const std::unordered_map<std::string, std::string> register_exprs = {
    { "pc", "epc" }, { "ra", "ra" }, { "sp", "sp" },   { "gp", "gp" },
    { "tp", "tp" },  { "t0", "t0" }, { "t1", "t1" },   { "t2", "t2" },
    { "s0", "s0" },  { "s1", "s1" }, { "a0", "a0" },   { "a1", "a1" },
    { "a2", "a2" },  { "a3", "a3" }, { "a4", "a4" },   { "a5", "a5" },
    { "a6", "a6" },  { "a7", "a7" }, { "s2", "s2" },   { "s3", "s3" },
    { "s4", "s4" },  { "s5", "s5" }, { "s6", "s6" },   { "s7", "s7" },
    { "s8", "s8" },  { "s9", "s9" }, { "s10", "s10" }, { "s11", "s11" },
    { "t3", "t3" },  { "t4", "t4" }, { "t5", "t5" },   { "t6", "t6" },
  };
  auto it = register_exprs.find(name);
  if (it != register_exprs.end()) {
    return it->second;
  }
  return std::nullopt;
}

template <>
std::optional<size_t> Arch<Machine::RISCV64>::register_to_pt_regs_offset(
    const std::string& name)
{
  static const std::unordered_map<std::string, size_t> register_offsets = {
    { "pc", 0 },   { "ra", 8 },    { "sp", 16 },   { "gp", 24 },  { "tp", 32 },
    { "t0", 40 },  { "t1", 48 },   { "t2", 56 },   { "s0", 64 },  { "s1", 72 },
    { "a0", 80 },  { "a1", 88 },   { "a2", 96 },   { "a3", 104 }, { "a4", 112 },
    { "a5", 120 }, { "a6", 128 },  { "a7", 136 },  { "s2", 144 }, { "s3", 152 },
    { "s4", 160 }, { "s5", 168 },  { "s6", 176 },  { "s7", 184 }, { "s8", 192 },
    { "s9", 200 }, { "s10", 208 }, { "s11", 216 }, { "t3", 224 }, { "t4", 232 },
    { "t5", 240 }, { "t6", 248 },
  };
  auto it = register_offsets.find(name);
  if (it != register_offsets.end()) {
    return it->second;
  }
  return std::nullopt;
}

template <>
const std::vector<std::string>& Arch<Machine::RISCV64>::arguments()
{
  static std::vector<std::string> args = {
    "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
  };
  return args;
}

template <>
size_t Arch<Machine::RISCV64>::argument_stack_offset()
{
  return 0;
}

template <>
std::string Arch<Machine::RISCV64>::return_value()
{
  return "a0";
}

template <>
std::string Arch<Machine::RISCV64>::pc_value()
{
  return "pc";
}

template <>
std::string Arch<Machine::RISCV64>::sp_value()
{
  return "sp";
}

template <>
const std::unordered_set<std::string>& Arch<
    Machine::RISCV64>::watchpoint_modes()
{
  static std::unordered_set<std::string> valid_modes = {};
  return valid_modes;
}

} // namespace bpftrace::arch
