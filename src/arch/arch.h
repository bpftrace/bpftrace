#pragma once

#include <string>

namespace bpftrace {
namespace arch {

int offset(std::string reg_name);
int max_arg();
int arg_offset(int arg_num);
int ret_offset();
int pc_offset();
std::string name();

} // namespace arch
} // namespace bpftrace
