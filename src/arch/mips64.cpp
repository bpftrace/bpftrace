#include "arch.h"

#include <algorithm>
#include <array>

// SP + 8 points to the first argument that is passed on the stack
#define ARG0_STACK 8

namespace bpftrace {
namespace arch {

// clang-format off
static std::array<std::string, 32> registers = {
  "zero",
  "at",
  "v0",
  "v1",
  "a0",
  "a1",
  "a2",
  "a3",
  "a4",
  "a5",
  "a6",
  "a7",
  "t0",
  "t1",
  "t2",
  "t3",
  "s0",
  "s1",
  "s2",
  "s3",
  "s4",
  "s5",
  "s6",
  "s7",
  "t8",
  "t9",
  "k0",
  "k1",
  "gp",
  "sp",
  "fp/s8",
  "ra",
};

// Alternative register names that match struct pt_regs
static std::array<std::string, 32> ptrace_registers = {
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
  "regs[31]", 
};

static std::array<std::string, 8> arg_registers = {
  "a0",
  "a1",
  "a2",
  "a3",
  "a4",
  "a5",
  "a6",
  "a7",
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
    {
      return -1;
    }
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

#pragma GCC push_options
#pragma GCC optimize("O0")
static int *__getpc(void)
{
  int *rtaddr;

  __asm__ volatile("move %0, $31" : "=r"(rtaddr));
  return rtaddr;
}
#pragma GCC pop_options

int pc_offset()
{
  int *retAddr, pc;

  retAddr = __getpc();
  pc = *retAddr;

  return pc;
}

int ret_offset()
{
  return offset("v0");
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
  return std::string("mips64");
}

} // namespace arch
} // namespace bpftrace
