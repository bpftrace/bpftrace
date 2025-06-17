#include <unordered_map>

#include "arch.h"

namespace bpftrace::arch {

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
std::optional<std::string> Arch<Machine::MIPS64>::register_to_pt_regs_expr(
    const std::string& name)
{
  static const std::unordered_map<std::string, std::string> register_exprs = {
    { "zero", "regs[0]" },
    { "at", "regs[1]" },
    { "v0", "regs[2]" },
    { "v1", "regs[3]" },
    { "a0", "regs[4]" },
    { "a1", "regs[5]" },
    { "a2", "regs[6]" },
    { "a3", "regs[7]" },
    { "a4", "regs[8]" },
    { "a5", "regs[9]" },
    { "a6", "regs[10]" },
    { "a7", "regs[11]" },
    { "t0", "regs[12]" },
    { "t1", "regs[13]" },
    { "t2", "regs[14]" },
    { "t3", "regs[15]" },
    { "s0", "regs[16]" },
    { "s1", "regs[17]" },
    { "s2", "regs[18]" },
    { "s3", "regs[19]" },
    { "s4", "regs[20]" },
    { "s5", "regs[21]" },
    { "s6", "regs[22]" },
    { "s7", "regs[23]" },
    { "t8", "regs[24]" },
    { "t9", "regs[25]" },
    { "k0", "regs[26]" },
    { "k1", "regs[27]" },
    { "gp", "regs[28]" },
    { "sp", "regs[29]" },
    { "fp", "regs[30]" },
    { "fp/s8", "regs[30]" },
    { "ra", "regs[31]" },

    // Support full expressions as string literals.
    { "regs[0]", "regs[0]" },
    { "regs[1]", "regs[1]" },
    { "regs[2]", "regs[2]" },
    { "regs[3]", "regs[3]" },
    { "regs[4]", "regs[4]" },
    { "regs[5]", "regs[5]" },
    { "regs[6]", "regs[6]" },
    { "regs[7]", "regs[7]" },
    { "regs[8]", "regs[8]" },
    { "regs[9]", "regs[9]" },
    { "regs[10]", "regs[10]" },
    { "regs[11]", "regs[11]" },
    { "regs[12]", "regs[12]" },
    { "regs[13]", "regs[13]" },
    { "regs[14]", "regs[14]" },
    { "regs[15]", "regs[15]" },
    { "regs[16]", "regs[16]" },
    { "regs[17]", "regs[17]" },
    { "regs[18]", "regs[18]" },
    { "regs[19]", "regs[19]" },
    { "regs[20]", "regs[20]" },
    { "regs[21]", "regs[21]" },
    { "regs[22]", "regs[22]" },
    { "regs[23]", "regs[23]" },
    { "regs[24]", "regs[24]" },
    { "regs[25]", "regs[25]" },
    { "regs[26]", "regs[26]" },
    { "regs[27]", "regs[27]" },
    { "regs[28]", "regs[28]" },
    { "regs[29]", "regs[29]" },
    { "regs[30]", "regs[30]" },
    { "regs[31]", "regs[31]" },

    // System registers.
    { "cp0_status", "cp0_status" },
    { "hi", "hi" },
    { "lo", "lo" },
    { "cp0_badvaddr", "cp0_badvaddr" },
    { "cp0_cause", "cp0_cause" },
    { "cp0_epc", "cp0_epc" },
  };

  auto it = register_exprs.find(name);
  if (it != register_exprs.end()) {
    return it->second;
  }
  return std::nullopt;
}

template <>
std::optional<size_t> Arch<Machine::MIPS64>::register_to_pt_regs_offset(
    const std::string& name)
{
  static const std::unordered_map<std::string, size_t> register_offsets = {
    { "zero", 0 },
    { "at", 8 },
    { "v0", 16 },
    { "v1", 24 },
    { "a0", 32 },
    { "a1", 40 },
    { "a2", 48 },
    { "a3", 56 },
    { "a4", 64 },
    { "a5", 72 },
    { "a6", 80 },
    { "a7", 88 },
    { "t0", 96 },
    { "t1", 104 },
    { "t2", 112 },
    { "t3", 120 },
    { "s0", 128 },
    { "s1", 136 },
    { "s2", 144 },
    { "s3", 152 },
    { "s4", 160 },
    { "s5", 168 },
    { "s6", 176 },
    { "s7", 184 },
    { "t8", 192 },
    { "t9", 200 },
    { "k0", 208 },
    { "k1", 216 },
    { "gp", 224 },
    { "sp", 232 },
    { "fp", 240 },
    { "fp/s8", 240 },
    { "ra", 248 },

    // Support full expressions as literals.
    { "regs[0]", 0 },
    { "regs[1]", 8 },
    { "regs[2]", 16 },
    { "regs[3]", 24 },
    { "regs[4]", 32 },
    { "regs[5]", 40 },
    { "regs[6]", 48 },
    { "regs[7]", 56 },
    { "regs[8]", 64 },
    { "regs[9]", 72 },
    { "regs[10]", 80 },
    { "regs[11]", 88 },
    { "regs[12]", 96 },
    { "regs[13]", 104 },
    { "regs[14]", 112 },
    { "regs[15]", 120 },
    { "regs[16]", 128 },
    { "regs[17]", 136 },
    { "regs[18]", 144 },
    { "regs[19]", 152 },
    { "regs[20]", 160 },
    { "regs[21]", 168 },
    { "regs[22]", 176 },
    { "regs[23]", 184 },
    { "regs[24]", 192 },
    { "regs[25]", 200 },
    { "regs[26]", 208 },
    { "regs[27]", 216 },
    { "regs[28]", 224 },
    { "regs[29]", 232 },
    { "regs[30]", 240 },
    { "regs[31]", 248 },

    // System registers.
    { "cp0_status", 256 },
    { "hi", 264 },
    { "lo", 272 },
    { "cp0_badvaddr", 280 },
    { "cp0_cause", 288 },
    { "cp0_epc", 296 },
  };

  auto it = register_offsets.find(name);
  if (it != register_offsets.end()) {
    return it->second;
  }
  return std::nullopt;
}

template <>
const std::vector<std::string>& Arch<Machine::MIPS64>::arguments()
{
  static std::vector<std::string> args = {
    "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
  };
  return args;
}

template <>
size_t Arch<Machine::MIPS64>::argument_stack_offset()
{
  return 8;
}

template <>
std::string Arch<Machine::MIPS64>::return_value()
{
  return "v0";
}

template <>
std::string Arch<Machine::MIPS64>::pc_value()
{
  return "cp0_epc";
}

template <>
std::string Arch<Machine::MIPS64>::sp_value()
{
  return "sp";
}

template <>
const std::unordered_set<std::string>& Arch<Machine::MIPS64>::watchpoint_modes()
{
  static std::unordered_set<std::string> valid_modes = {};
  return valid_modes;
}

} // namespace bpftrace::arch
