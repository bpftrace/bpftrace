#include "arch.h"

#include <algorithm>
#include <array>

namespace bpftrace {
namespace arch {

static std::array<std::string, 35> registers = {
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
  "r31",
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

std::string name()
{
  return std::string("aarch64");
}

} // namespace arch
} // namespace bpftrace
