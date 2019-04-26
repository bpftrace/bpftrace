#pragma once

#include <tuple>
#include <string>
#include <vector>
#include <iostream>
#include <sys/utsname.h>

namespace bpftrace {

typedef std::tuple<std::string, std::string> usdt_probe_pair;

class USDTHelper
{
public:
  static usdt_probe_pair find(void *ctx, int pid, std::string name);
};

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


bool has_wildcard(const std::string &str);
std::vector<std::string> split_string(const std::string &str, char delimiter);
bool wildcard_match(const std::string &str, std::vector<std::string> &tokens, bool start_wildcard, bool end_wildcard);
std::vector<int> get_online_cpus();
std::vector<int> get_possible_cpus();
bool is_dir(const std::string& path);
std::tuple<std::string, std::string> get_kernel_dirs(const struct utsname& utsname);
std::vector<std::string> get_kernel_cflags(
    const char* uname_machine,
    const std::string& ksrc,
    const std::string& kobj);
std::string is_deprecated(std::string &str);
std::string exec_system(const char* cmd);
std::string resolve_binary_path(const std::string& cmd);
void cat_file(const char *filename);

// trim from end of string (right)
inline std::string& rtrim(std::string& s)
{
  s.erase(s.find_last_not_of(" ") + 1);
  return s;
}

// trim from beginning of string (left)
inline std::string& ltrim(std::string& s)
{
  s.erase(0, s.find_first_not_of(" "));
  return s;
}

// trim from both ends of string (right then left)
inline std::string& trim(std::string& s)
{
  return ltrim(rtrim(s));
}

} // namespace bpftrace
