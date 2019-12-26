#include "arch.h"

#include <algorithm>
#include <array>
#include <set>
#include <vector>

#define ARG_REGISTERS 5
// For s390x, r2-r6 registers are used as function arguments, then the extra
// arguments can be found starting at sp+160
#define ARG0_STACK 160

namespace bpftrace {
namespace arch {

// clang-format off
static std::vector<std::set<std::string>> registers = {
  // Breakpoint event address
  { "arg" },
  { "pswmask" },
  // Instruction address
  { "pswaddr" },
  { "r0", "gprs[0]" },
  { "r1", "gprs[1]" },
  { "r2", "gprs[2]" },
  { "r3", "gprs[3]" },
  { "r4", "gprs[4]" },
  { "r5", "gprs[5]" },
  { "r6", "gprs[6]" },
  { "r7", "gprs[7]" },
  { "r8", "gprs[8]" },
  { "r9", "gprs[9]" },
  { "r10", "gprs[10]" },
  { "r11", "gprs[11]" },
  { "r12", "gprs[12]" },
  { "r13", "gprs[13]" },
  { "r14", "gprs[14]" },
  { "r15", "gprs[15]" }
};

static std::array<std::string, ARG_REGISTERS> arg_registers = {
  "r2",
  "r3",
  "r4",
  "r5",
  "r6",
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
  return offset("r2");
}

int pc_offset()
{
  return offset("pswaddr");
}

int sp_offset()
{
  return offset("r15");
}

int arg_stack_offset()
{
  return ARG0_STACK / 8;
}

std::string name()
{
  return std::string("s390x");
}

std::vector<std::string> invalid_watchpoint_modes()
{
  throw std::runtime_error(
      "Watchpoints are not supported on this architecture");
}

} // namespace arch
} // namespace bpftrace
