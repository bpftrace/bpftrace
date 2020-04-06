#include "arch.h"

#include <algorithm>
#include <array>

// For little endian 64 bit, sp + 32 + 8 regs save area + argX
#define ARG0_STACK_LE 96
// For big endian 64 bit, sp + 48 + 8 regs save area + argX
#define ARG0_STACK_BE 112

namespace bpftrace {
namespace arch {

// clang-format off
static std::array<std::string, 44> registers = {
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
  "nip",
  "msr",
  "orig_gpr3",
  "ctr",
  "link",
  "xer",
  "ccr",
  "softe",
  "trap",
  "dar",
  "dsisr",
  "result",
};

static std::array<std::string, 8> arg_registers = {
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

} // namespace arch
} // namespace bpftrace
