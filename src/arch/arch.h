#pragma once

#include <string>

namespace bpftrace {
namespace arch {

// Offsets are based off the pt_regs struct from the Linux kernel
int max_arg();
int arg_offset(int arg_num);
int ret_offset();
int pc_offset();
int sp_offset();
std::string name();

} // namespace arch
} // namespace bpftrace
