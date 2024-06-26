#pragma once

#include <cstdint>
#include <cstring>
#include <exception>
#include <functional>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <sys/utsname.h>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "filesystem.h"

namespace bpftrace {

struct vmlinux_location {
  const char *path; // path with possible "%s" format to be replaced current
                    // release
  bool raw;         // file is either as ELF (false) or raw BTF data (true)
};
extern const struct vmlinux_location vmlinux_locs[];
class MountNSException : public std::exception {
public:
  MountNSException(const std::string &msg) : msg_(msg)
  {
  }

  const char *what() const noexcept override
  {
    return msg_.c_str();
  }

private:
  std::string msg_;
};

class EnospcException : public std::runtime_error {
public:
  // C++11 feature: bring base class constructor into scope to automatically
  // forward constructor calls to base class
  using std::runtime_error::runtime_error;
};

// Use this to end bpftrace execution due to a user error.
// These should be caught at a high level only e.g. main.cpp or bpftrace.cpp
class FatalUserException : public std::runtime_error {
public:
  // C++11 feature: bring base class constructor into scope to automatically
  // forward constructor calls to base class
  using std::runtime_error::runtime_error;
};

class StdioSilencer {
public:
  StdioSilencer() = default;
  ~StdioSilencer();
  void silence();

protected:
  FILE *ofile;

private:
  int old_stdio_ = -1;
};

class StderrSilencer : public StdioSilencer {
public:
  StderrSilencer()
  {
    ofile = stderr;
  }
};

class StdoutSilencer : public StdioSilencer {
public:
  StdoutSilencer()
  {
    ofile = stdout;
  }
};

// Helper class to convert a pointer to an `std::istream`
class Membuf : public std::streambuf {
public:
  Membuf(uint8_t *begin, uint8_t *end)
  {
    auto b = reinterpret_cast<char *>(begin);
    auto e = reinterpret_cast<char *>(end);
    this->setg(b, b, e);
  }
};

// Hack used to suppress build warning related to #474
template <typename new_signature, typename old_signature>
new_signature cast_signature(old_signature func)
{
#if __GNUC__ >= 8
  _Pragma("GCC diagnostic push")
      _Pragma("GCC diagnostic ignored \"-Wcast-function-type\"")
#endif
          return reinterpret_cast<new_signature>(func);
#if __GNUC__ >= 8
  _Pragma("GCC diagnostic pop")
#endif
}

struct DeprecatedName {
  std::string old_name;
  std::string new_name;
  bool show_warning = true;
  bool replace_by_new_name = true;

  bool matches(const std::string &name) const
  {
    // We allow a prefix match to match against builtins with number (argX)
    if (old_name.back() == '*') {
      std::string_view old_name_view{ old_name.c_str(), old_name.size() - 1 };
      return name.rfind(old_name_view) == 0;
    }

    return name == old_name;
  }
};

typedef std::unordered_map<std::string, std::unordered_set<std::string>>
    FuncsModulesMap;

struct KConfig {
  KConfig();
  bool has_value(const std::string &name, const std::string &value) const
  {
    auto c = config.find(name);
    return c != config.end() && c->second == value;
  }

  std::unordered_map<std::string, std::string> config;
};

static std::vector<DeprecatedName> DEPRECATED_LIST = {
  { "sarg*", "*(reg(\"sp\") + <stack_offset>)", true, false }
};

static std::vector<std::string> UNSAFE_BUILTIN_FUNCS = {
  "system",
  "signal",
  "override",
};

static std::vector<std::string> COMPILE_TIME_FUNCS = { "cgroupid" };

static std::vector<std::string> UPROBE_LANGS = { "cpp" };

static const std::set<std::string> RECURSIVE_KERNEL_FUNCS = {
  "vmlinux:_raw_spin_lock",
  "vmlinux:_raw_spin_lock_irqsave",
  "vmlinux:_raw_spin_unlock_irqrestore",
  "vmlinux:queued_spin_lock_slowpath",
};

void get_uint64_env_var(const ::std::string &str,
                        const std::function<void(uint64_t)> &cb);
void get_bool_env_var(const ::std::string &str,
                      const std::function<void(bool)> &cb);
// Tries to find a file in $PATH
std::optional<std_filesystem::path> find_in_path(std::string_view name);
// Finds a file in the same directory as running binary
std::optional<std_filesystem::path> find_near_self(std::string_view name);
std::string get_pid_exe(pid_t pid);
std::string get_pid_exe(const std::string &pid);
std::string get_proc_maps(const std::string &pid);
std::string get_proc_maps(pid_t pid);
bool has_wildcard(const std::string &str);
std::vector<std::string> split_string(const std::string &str,
                                      char delimiter,
                                      bool remove_empty = false);
std::string erase_prefix(std::string &str);
bool wildcard_match(const std::string &str,
                    std::vector<std::string> &tokens,
                    bool start_wildcard,
                    bool end_wildcard);
std::vector<std::string> get_wildcard_tokens(const std::string &input,
                                             bool &start_wildcard,
                                             bool &end_wildcard);
std::vector<int> get_online_cpus();
std::vector<int> get_possible_cpus();
bool is_dir(const std::string &path);
bool file_exists_and_ownedby_root(const char *f);
bool get_kernel_dirs(const struct utsname &utsname,
                     std::string &ksrc,
                     std::string &kobj);
std::vector<std::string> get_kernel_cflags(const char *uname_machine,
                                           const std::string &ksrc,
                                           const std::string &kobj,
                                           const KConfig &kconfig);
std::string get_cgroup_path_in_hierarchy(uint64_t cgroupid,
                                         std::string base_path);
std::vector<std::pair<std::string, std::string>> get_cgroup_hierarchy_roots();
std::vector<std::pair<std::string, std::string>> get_cgroup_paths(
    uint64_t cgroupid,
    std::string filter);
bool is_module_loaded(const std::string &module);
FuncsModulesMap parse_traceable_funcs();
const std::string &is_deprecated(const std::string &str);
bool is_recursive_func(const std::string &func_name);
bool is_unsafe_func(const std::string &func_name);
bool is_compile_time_func(const std::string &func_name);
bool is_supported_lang(const std::string &lang);
bool is_type_name(std::string_view str);
std::string exec_system(const char *cmd);
bool is_exe(const std::string &path);
std::vector<std::string> resolve_binary_path(const std::string &cmd);
std::vector<std::string> resolve_binary_path(const std::string &cmd, int pid);
std::string path_for_pid_mountns(int pid, const std::string &path);
void cat_file(const char *filename, size_t, std::ostream &);
std::string str_join(const std::vector<std::string> &list,
                     const std::string &delim);
bool is_numeric(const std::string &str);
bool symbol_has_cpp_mangled_signature(const std::string &sym_name);
std::optional<pid_t> parse_pid(const std::string &str, std::string &err);
std::string hex_format_buffer(const char *buf,
                              size_t size,
                              bool keep_ascii = true,
                              bool escape_hex = true);
std::optional<std::string> abs_path(const std::string &rel_path);
bool symbol_has_module(const std::string &symbol);
std::pair<std::string, std::string> split_symbol_module(
    const std::string &symbol);
std::tuple<std::string, std::string, std::string> split_addrrange_symbol_module(
    const std::string &symbol);

std::vector<std::string> get_mapped_paths_for_pid(pid_t pid);
std::vector<std::string> get_mapped_paths_for_running_pids();
struct elf_symbol {
  std::string name;
  uintptr_t start;
  uintptr_t end;
};
// Get all symbols from an ELF module together with their address ranges in
// the form of a map sorted by start address.
// Note: the map uses std::greater as comparator to allow resolving of an
// address inside a range using std::map::lower_bound.
std::map<uintptr_t, elf_symbol, std::greater<>> get_symbol_table_for_elf(
    const std::string &elf_file);
std::vector<int> get_pids_for_program(const std::string &program);
std::vector<int> get_all_running_pids();

std::string sanitise_bpf_program_name(const std::string &name);
// Generate object file function name for a given probe
inline std::string get_function_name_for_probe(
    const std::string &probe_name,
    int index,
    std::optional<int> usdt_location_index = std::nullopt)
{
  auto ret = sanitise_bpf_program_name(probe_name);

  if (usdt_location_index)
    ret += "_loc" + std::to_string(*usdt_location_index);

  ret += "_" + std::to_string(index);

  return ret;
}

inline std::string get_section_name(const std::string &function_name)
{
  return "s_" + function_name;
}

inline std::string get_watchpoint_setup_probe_name(
    const std::string &probe_name)
{
  return probe_name + "_wp_setup";
}

inline std::string get_function_name_for_watchpoint_setup(
    const std::string &probe_name,
    int index)
{
  return get_function_name_for_probe(
      get_watchpoint_setup_probe_name(probe_name), index);
}

// trim from end of string (right)
inline std::string &rtrim(std::string &s)
{
  s.erase(s.find_last_not_of(" ") + 1);
  return s;
}

// trim from beginning of string (left)
inline std::string &ltrim(std::string &s)
{
  s.erase(0, s.find_first_not_of(" "));
  return s;
}

// trim from both ends of string (right then left)
inline std::string &trim(std::string &s)
{
  return ltrim(rtrim(s));
}

template <typename T>
T read_data(const void *src)
{
  T v;
  std::memcpy(&v, src, sizeof(v));
  return v;
}

enum KernelVersionMethod { vDSO, UTS, File, None };
uint32_t kernel_version(KernelVersionMethod);

template <typename T>
T reduce_value(const std::vector<uint8_t> &value, int nvalues)
{
  T sum = 0;
  for (int i = 0; i < nvalues; i++) {
    sum += read_data<T>(value.data() + i * sizeof(T));
  }
  return sum;
}
int64_t min_value(const std::vector<uint8_t> &value, int nvalues);
uint64_t max_value(const std::vector<uint8_t> &value, int nvalues);

// Combination of 2 hashes
// The algorithm is taken from boost::hash_combine
template <class T>
inline void hash_combine(std::size_t &seed, const T &value)
{
  std::hash<T> hasher;
  seed ^= hasher(value) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
}

} // namespace bpftrace
