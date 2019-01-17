#pragma once

#include <string>
#include <vector>

namespace bpftrace {

inline std::string GetProviderFromPath(std::string path);
bool has_wildcard(const std::string &str);
std::vector<int> get_online_cpus();
std::vector<int> get_possible_cpus();
std::vector<std::string> get_kernel_cflags(
    const char* uname_machine,
    const std::string& kdir);

} // namespace bpftrace

#include "utils-inl.h"
