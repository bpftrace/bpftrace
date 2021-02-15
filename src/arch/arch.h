#pragma once

#include <stdexcept>
#include <string>
#include <vector>

namespace bpftrace {
namespace arch {

int offset(std::string reg_name);
int max_arg();
int arg_offset(int arg_num);
int ret_offset();
int pc_offset();
int sp_offset();
int arg_stack_offset();
std::string name();
// Each string is lexicographically sorted by character
std::vector<std::string> invalid_watchpoint_modes();

} // namespace arch
} // namespace bpftrace
