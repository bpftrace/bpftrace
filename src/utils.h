#pragma once

#include <string>
#include <vector>
#include <iostream>

namespace bpftrace {

struct DeprecatedName
{
  std::string old_name;
  std::string new_name;
  bool show_warning = true;
};

static std::vector<DeprecatedName> DEPRECATED_LIST =
{
  { "stack", "kstack"},
  { "sym", "ksym"},
};


inline std::string GetProviderFromPath(std::string path);
bool has_wildcard(const std::string &str);
std::vector<int> get_online_cpus();
std::vector<int> get_possible_cpus();
std::vector<std::string> get_kernel_cflags(
    const char* uname_machine,
    const std::string& kdir);
std::string is_deprecated(std::string &str);

} // namespace bpftrace

#include "utils-inl.h"
