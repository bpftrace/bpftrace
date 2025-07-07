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
std::optional<std::string> Arch<Machine::PPC64>::register_to_pt_regs_expr(
    const std::string& name)
{
  // PowerPC pt_regs structure field mapping
  static const std::unordered_map<std::string, std::string> register_exprs = {
    { "r0", "gpr[0]" },
    { "r1", "gpr[1]" },
    { "r2", "gpr[2]" },
    { "r3", "gpr[3]" },
    { "r4", "gpr[4]" },
    { "r5", "gpr[5]" },
    { "r6", "gpr[6]" },
    { "r7", "gpr[7]" },
    { "r8", "gpr[8]" },
    { "r9", "gpr[9]" },
    { "r10", "gpr[10]" },
    { "r11", "gpr[11]" },
    { "r12", "gpr[12]" },
    { "r13", "gpr[13]" },
    { "r14", "gpr[14]" },
    { "r15", "gpr[15]" },
    { "r16", "gpr[16]" },
    { "r17", "gpr[17]" },
    { "r18", "gpr[18]" },
    { "r19", "gpr[19]" },
    { "r20", "gpr[20]" },
    { "r21", "gpr[21]" },
    { "r22", "gpr[22]" },
    { "r23", "gpr[23]" },
    { "r24", "gpr[24]" },
    { "r25", "gpr[25]" },
    { "r26", "gpr[26]" },
    { "r27", "gpr[27]" },
    { "r28", "gpr[28]" },
    { "r29", "gpr[29]" },
    { "r30", "gpr[30]" },
    { "r31", "gpr[31]" },
    { "nip", "nip" },
    { "msr", "msr" },
    { "orig_gpr3", "orig_gpr3" },
    { "ctr", "ctr" },
    { "link", "link" },
    { "xer", "xer" },
    { "ccr", "ccr" },
    { "softe", "softe" },
    { "trap", "trap" },
    { "dar", "dar" },
    { "dsisr", "dsisr" },
    { "result", "result" },
  };
  auto it = register_exprs.find(name);
  if (it != register_exprs.end()) {
    return it->second;
  }
  return std::nullopt;
}

template <>
std::optional<size_t> Arch<Machine::PPC64>::register_to_pt_regs_offset(
    const std::string& name)
{
  static const std::unordered_map<std::string, size_t> register_offsets = {
    { "r0", 0 },     { "r1", 8 },    { "r2", 16 },         { "r3", 24 },
    { "r4", 32 },    { "r5", 40 },   { "r6", 48 },         { "r7", 56 },
    { "r8", 64 },    { "r9", 72 },   { "r10", 80 },        { "r11", 88 },
    { "r12", 96 },   { "r13", 104 }, { "r14", 112 },       { "r15", 120 },
    { "r16", 128 },  { "r17", 136 }, { "r18", 144 },       { "r19", 152 },
    { "r20", 160 },  { "r21", 168 }, { "r22", 176 },       { "r23", 184 },
    { "r24", 192 },  { "r25", 200 }, { "r26", 208 },       { "r27", 216 },
    { "r28", 224 },  { "r29", 232 }, { "r30", 240 },       { "r31", 248 },
    { "nip", 256 },  { "msr", 264 }, { "orig_gpr3", 272 }, { "ctr", 280 },
    { "link", 288 }, { "xer", 296 }, { "ccr", 304 },       { "softe", 312 },
    { "trap", 320 }, { "dar", 328 }, { "dsisr", 336 },     { "result", 344 },
  };
  auto it = register_offsets.find(name);
  if (it != register_offsets.end()) {
    return it->second;
  }
  return std::nullopt;
}

template <>
const std::vector<std::string>& Arch<Machine::PPC64>::arguments()
{
  static std::vector<std::string> args = {
    "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10",
  };
  return args;
}

template <>
size_t Arch<Machine::PPC64>::argument_stack_offset()
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return 96; // Little endian: sp + 32 + 8 regs save area + argX
#else
  return 112; // Big endian: sp + 48 + 8 regs save area + argX
#endif // __BYTE_ORDER__
}

template <>
std::string Arch<Machine::PPC64>::return_value()
{
  return "r3";
}

template <>
std::string Arch<Machine::PPC64>::pc_value()
{
  return "nip";
}

template <>
std::string Arch<Machine::PPC64>::sp_value()
{
  return "r1";
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
