#pragma once

#include <vector>

namespace bpftrace::util {

std::vector<int> get_online_cpus();
std::vector<int> get_possible_cpus();
int get_max_cpu_id();

} // namespace bpftrace::util
