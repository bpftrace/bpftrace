#include <unordered_map>

#include "arch.h"

namespace bpftrace::arch {

template <>
size_t Arch<Machine::LOONGARCH64>::kernel_ptr_width()
{
  return 64;
}

template <>
const std::vector<std::string>& Arch<Machine::LOONGARCH64>::c_defs()
{
  static std::vector<std::string> defs = {
    "__TARGET_ARCH_loongarch",
  };
  return defs;
}

template <>
std::optional<std::string> Arch<Machine::LOONGARCH64>::register_to_pt_regs_expr(
    const std::string& name)
{
  static const std::unordered_map<std::string, std::string> register_exprs = {
    { "r0", "regs[0]" },
    { "r1", "regs[1]" },
    { "r2", "regs[2]" },
    { "r3", "regs[3]" },
    { "r4", "regs[4]" },
    { "r5", "regs[5]" },
    { "r6", "regs[6]" },
    { "r7", "regs[7]" },
    { "r8", "regs[8]" },
    { "r9", "regs[9]" },
    { "r10", "regs[10]" },
    { "r11", "regs[11]" },
    { "r12", "regs[12]" },
    { "r13", "regs[13]" },
    { "r14", "regs[14]" },
    { "r15", "regs[15]" },
    { "r16", "regs[16]" },
    { "r17", "regs[17]" },
    { "r18", "regs[18]" },
    { "r19", "regs[19]" },
    { "r20", "regs[20]" },
    { "r21", "regs[21]" },
    { "r22", "regs[22]" },
    { "r23", "regs[23]" },
    { "r24", "regs[24]" },
    { "r25", "regs[25]" },
    { "r26", "regs[26]" },
    { "r27", "regs[27]" },
    { "r28", "regs[28]" },
    { "r29", "regs[29]" },
    { "r30", "regs[30]" },
    { "r31", "regs[31]" },

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

    // Special registers.
    { "orig_a0", "orig_a0" },
    { "pc", "csr_era" },
  };
  auto it = register_exprs.find(name);
  if (it != register_exprs.end()) {
    return it->second;
  }
  return std::nullopt;
}

template <>
std::optional<size_t> Arch<Machine::LOONGARCH64>::register_to_pt_regs_offset(
    const std::string& name)
{
  static const std::unordered_map<std::string, size_t> register_offsets = {
    { "r0", 0 },
    { "r1", 8 },
    { "r2", 16 },
    { "r3", 24 },
    { "r4", 32 },
    { "r5", 40 },
    { "r6", 48 },
    { "r7", 56 },
    { "r8", 64 },
    { "r9", 72 },
    { "r10", 80 },
    { "r11", 88 },
    { "r12", 96 },
    { "r13", 104 },
    { "r14", 112 },
    { "r15", 120 },
    { "r16", 128 },
    { "r17", 136 },
    { "r18", 144 },
    { "r19", 152 },
    { "r20", 160 },
    { "r21", 168 },
    { "r22", 176 },
    { "r23", 184 },
    { "r24", 192 },
    { "r25", 200 },
    { "r26", 208 },
    { "r27", 216 },
    { "r28", 224 },
    { "r29", 232 },
    { "r30", 240 },
    { "r31", 248 },

    // Support full expressions as string literals.
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

    // Special registers.
    { "orig_a0", 256 },
    { "pc", 264 },
  };
  auto it = register_offsets.find(name);
  if (it != register_offsets.end()) {
    return it->second;
  }
  return std::nullopt;
}

template <>
const std::vector<std::string>& Arch<Machine::LOONGARCH64>::arguments()
{
  static std::vector<std::string> args = {
    "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11",
  };
  return args;
}

template <>
size_t Arch<Machine::LOONGARCH64>::argument_stack_offset()
{
  return 0;
}

template <>
std::string Arch<Machine::LOONGARCH64>::return_value()
{
  return "r4";
}

template <>
std::string Arch<Machine::LOONGARCH64>::pc_value()
{
  return "pc";
}

template <>
std::string Arch<Machine::LOONGARCH64>::sp_value()
{
  return "r3";
}

template <>
const std::unordered_set<std::string>& Arch<
    Machine::LOONGARCH64>::watchpoint_modes()
{
  static std::unordered_set<std::string> valid_modes = {};
  return valid_modes;
}

} // namespace bpftrace::arch
