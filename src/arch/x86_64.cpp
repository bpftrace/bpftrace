#include "arch.h"

#include <algorithm>
#include <array>

namespace bpftrace {
namespace arch {

static std::array<std::string, 27> registers = {
  "r15",
  "r14",
  "r13",
  "r12",
  "bp",
  "bx",
  "r11",
  "r10",
  "r9",
  "r8",
  "ax",
  "cx",
  "dx",
  "si",
  "di",
  "orig_ax",
  "ip",
  "cs",
  "flags",
  "sp",
  "ss",
  "fs_base",
  "gs_base",
  "ds",
  "es",
  "fs",
  "gs",
};

static std::array<std::string, 6> arg_registers = {
  "di",
  "si",
  "dx",
  "cx",
  "r8",
  "r9",
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
  return offset("ax");
}

int pc_offset()
{
  return offset("ip");
}

std::string name()
{
  return std::string("x86_64");
}

} // namespace arch
} // namespace bpftrace
