#pragma once

#include <string>
#include <unordered_set>

namespace bpftrace::arch {

int offset(std::string reg_name);
int max_arg();
int arg_offset(int arg_num);
int ret_offset();
int pc_offset();
int sp_offset();
int arg_stack_offset();
std::string name();

// Returns the set of valid watchpoint modes.
const std::unordered_set<std::string> &watchpoint_modes();

// Returns the width in bits of kernel pointers.
int get_kernel_ptr_width();

} // namespace bpftrace::arch
