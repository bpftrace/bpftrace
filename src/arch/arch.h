#pragma once

#include <string>
#include <vector>

namespace bpftrace::arch {

int offset(std::string reg_name);
int max_arg();
int arg_offset(int arg_num);
int ret_offset();
int pc_offset();
int sp_offset();
int arg_stack_offset();
std::string name();

// Determine if the given watchpoint mode is valid.
bool is_watchpoint_mode_valid(const std::string &mode);

// Returns the width in bits of kernel pointers.
int get_kernel_ptr_width();

} // namespace bpftrace::arch
