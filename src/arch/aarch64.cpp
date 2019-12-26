#include "arch.h"

#include <algorithm>
#include <array>

// SP points to the first argument that is passed on the stack
#define ARG0_STACK 0

namespace bpftrace {
namespace arch {

// clang-format off
static std::array<std::string, 34> registers = {
  "r0",
  "r1",
  "r2",
  "r3",
  "r4",
  "r5",
  "r6",
  "r7",
  "r8",
  "r9",
  "r10",
  "r11",
  "r12",
  "r13",
  "r14",
  "r15",
  "r16",
  "r17",
  "r18",
  "r19",
  "r20",
  "r21",
  "r22",
  "r23",
  "r24",
  "r25",
  "r26",
  "r27",
  "r28",
  "r29",
  "r30",
  "sp",
  "pc",
  "pstate",
};

// Alternative register names that match struct pt_regs
static std::array<std::string, 34> ptrace_registers = {
  "regs[0]",
  "regs[1]",
  "regs[2]",
  "regs[3]",
  "regs[4]",
  "regs[5]",
  "regs[6]",
  "regs[7]",
  "regs[8]",
  "regs[9]",
  "regs[10]",
  "regs[11]",
  "regs[12]",
  "regs[13]",
  "regs[14]",
  "regs[15]",
  "regs[16]",
  "regs[17]",
  "regs[18]",
  "regs[19]",
  "regs[20]",
  "regs[21]",
  "regs[22]",
  "regs[23]",
  "regs[24]",
  "regs[25]",
  "regs[26]",
  "regs[27]",
  "regs[28]",
  "regs[29]",
  "regs[30]",
  "sp",
  "pc",
  "pstate",
};

static std::array<std::string, 8> arg_registers = {
  "r0",
  "r1",
  "r2",
  "r3",
  "r4",
  "r5",
  "r6",
  "r7",
};
// clang-format on

int offset(std::string reg_name)
{
  auto it = find(registers.begin(), registers.end(), reg_name);
  if (it == registers.end())
  {
    // Also allow register names that match the fields in struct pt_regs.
    // These appear in USDT probe arguments.
    it = find(ptrace_registers.begin(), ptrace_registers.end(), reg_name);
    if (it == ptrace_registers.end())
      return -1;
    return distance(ptrace_registers.begin(), it);
  }
  return distance(registers.begin(), it);
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
  return offset("r0");
}

int pc_offset()
{
  return offset("pc");
}

int sp_offset()
{
  return offset("sp");
}

int arg_stack_offset()
{
  return ARG0_STACK / 8;
}

std::string name()
{
  return std::string("aarch64");
}

std::vector<std::string> invalid_watchpoint_modes()
{
  // See arch/arm/kernel/hw_breakpoint.c:arch_build_bp_info in kernel source
  return std::vector<std::string>{
    "rx",
    "wx",
    "rwx",
  };
}

} // namespace arch
} // namespace bpftrace
