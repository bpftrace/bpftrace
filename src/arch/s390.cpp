#include "arch.h"

#include <algorithm>
#include <array>

#define REQ_REGISTERS 19
#define ARG_REGISTERS 5

namespace bpftrace {
namespace arch {

// clang-format off
static std::array<std::string, REQ_REGISTERS> registers = {
  // Breakpoint event address
  "arg",
  "pswmask",
  // Instruction address
  "pswaddr",
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
  auto it = find(registers.begin(), registers.end(), reg_name);
  if (it == registers.end())
    return -1;
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

std::string name()
{
  return std::string("s390x");
}

} // namespace arch
} // namespace bpftrace
