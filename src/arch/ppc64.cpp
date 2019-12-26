#include "arch.h"

#include <algorithm>
#include <array>
#include <set>
#include <vector>

#define ARG_REGISTERS 8
// For little endian 64 bit, sp + 32 + 8 regs save area + argX
#define ARG0_STACK_LE 96
// For big endian 64 bit, sp + 48 + 8 regs save area + argX
#define ARG0_STACK_BE 112

namespace bpftrace {
namespace arch {

// clang-format off
static std::vector<std::set<std::string>> registers = {
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
  { "nip" },
  { "msr" },
  { "orig_gpr3" },
  { "ctr" },
  { "link" },
  { "xer" },
  { "ccr" },
  { "softe" },
  { "trap" },
  { "dar" },
  { "dsisr" },
  { "result" },
};

static std::array<std::string, ARG_REGISTERS> arg_registers = {
  "r3",
  "r4",
  "r5",
  "r6",
  "r7",
  "r8",
  "r9",
  "r10",
};
// clang-format on

int offset(std::string reg_name)
{
  for (unsigned int i = 0; i < registers.size(); i++)
  {
    if (registers[i].count(reg_name))
      return i;
  }
  return -1;
}

int max_arg()
{
  return arg_registers.size() - 1;
}

int arg_offset(int arg_num)
{
  return offset(arg_registers.at(arg_num));
}

int ret_offset()
{
  return offset("r3");
}

int pc_offset()
{
  return offset("nip");
}

int sp_offset()
{
  return offset("r1");
}

int arg_stack_offset()
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return ARG0_STACK_LE / 8;
#else
  return ARG0_STACK_BE / 8;
#endif
}

std::string name()
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return std::string("ppc64le");
#else
  return std::string("ppc64");
#endif // __BYTE_ORDER__
}

std::vector<std::string> invalid_watchpoint_modes()
{
  throw std::runtime_error(
      "Watchpoints are not supported on this architecture");
}

} // namespace arch
} // namespace bpftrace
