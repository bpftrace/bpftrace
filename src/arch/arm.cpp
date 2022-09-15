#include "arch.h"

#include <algorithm>
#include <array>

// SP points to the first argument that is passed on the stack
#define ARG0_STACK 0

namespace bpftrace {
namespace arch {

// clang-format off
static std::array<std::string, 17> registers = {
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
  "fp",
  "ip",
  "sp",
  "lr",
  "pc",
  "cpsr",
};

static std::array<std::string, 4> arg_registers = {
  "r0",
  "r1",
  "r2",
  "r3",
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
  return ARG0_STACK / 4;
}

std::string name()
{
  return std::string("arm");
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
