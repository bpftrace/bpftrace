#include "arch.h"

#include <array>

namespace bpftrace {
namespace arch {

static std::array<int, 6> arg_offsets = {
  14, // di
  13, // si
  12, // dx
  11, // cx
   9, // r8
   8, // r9
};

int max_arg()
{
  return arg_offsets.size() - 1;
}

int arg_offset(int arg_num)
{
  return arg_offsets.at(arg_num);
}

int ret_offset()
{
  return 10; // ax
}

int pc_offset()
{
  return 16; // ip
}

int sp_offset()
{
  return 19; // sp
}

std::string name()
{
  return std::string("x86_64");
}

} // namespace arch
} // namespace bpftrace
