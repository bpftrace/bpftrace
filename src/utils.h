#pragma once

#include <cstring>
#include <exception>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <sys/utsname.h>
#include <tuple>
#include <unordered_set>
#include <vector>

namespace bpftrace {

struct vmlinux_location
{
  const char *path; // path with possible "%s" format to be replaced current
                    // release
  bool raw;         // file is either as ELF (false) or raw BTF data (true)
};
extern const struct vmlinux_location vmlinux_locs[];
class MountNSException : public std::exception
{
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

class InvalidPIDException : public std::exception
{
public:
  InvalidPIDException(const std::string &pid, const std::string &msg)
  {
    msg_ = "pid '" + pid + "' " + msg;
  }

  const char *what() const noexcept override
  {
    return msg_.c_str();
  }

private:
  std::string msg_;
};

class EnospcException : public std::runtime_error
{
public:
  // C++11 feature: bring base class constructor into scope to automatically
  // forward constructor calls to base class
  using std::runtime_error::runtime_error;
};

class StdioSilencer
{
public:
  StdioSilencer() = default;
  ~StdioSilencer();
  void silence();

protected:
  FILE *ofile;

private:
  int old_stdio_ = -1;
};

class StderrSilencer : public StdioSilencer
{
public:
  StderrSilencer()
  {
    ofile = stderr;
  }
};

class StdoutSilencer : public StdioSilencer
{
public:
  StdoutSilencer()
  {
    ofile = stdout;
  }
};

// Hack used to suppress build warning related to #474
template <typename new_signature, typename old_signature>
new_signature cast_signature(old_signature func) {
#if __GNUC__ >= 8
_Pragma("GCC diagnostic push")
_Pragma("GCC diagnostic ignored \"-Wcast-function-type\"")
#endif
  return reinterpret_cast<new_signature>(func);
#if __GNUC__ >= 8
_Pragma("GCC diagnostic pop")
#endif
}

struct DeprecatedName
{
  std::string old_name;
  std::string new_name;
  bool show_warning = true;
};

static std::vector<DeprecatedName> DEPRECATED_LIST =
{
};

static std::vector<std::string> UNSAFE_BUILTIN_FUNCS = {
  "system",
  "signal",
  "override",
};

static std::vector<std::string> COMPILE_TIME_FUNCS = { "cgroupid" };

bool get_uint64_env_var(const ::std::string &str, uint64_t &dest);
std::string get_pid_exe(pid_t pid);
std::string get_pid_exe(const std::string &pid);
bool has_wildcard(const std::string &str);
std::vector<std::string> split_string(const std::string &str,
                                      char delimiter,
                                      bool remove_empty = false);
std::string erase_prefix(std::string &str);
bool wildcard_match(const std::string &str,
                    std::vector<std::string> &tokens,
                    bool start_wildcard,
                    bool end_wildcard);
std::vector<int> get_online_cpus();
std::vector<int> get_possible_cpus();
bool is_dir(const std::string &path);
std::tuple<std::string, std::string> get_kernel_dirs(
    const struct utsname &utsname,
    bool unpack_kheaders);
std::vector<std::string> get_kernel_cflags(const char *uname_machine,
                                           const std::string &ksrc,
                                           const std::string &kobj);
std::unordered_set<std::string> get_traceable_funcs();
const std::string &is_deprecated(const std::string &str);
bool is_unsafe_func(const std::string &func_name);
bool is_compile_time_func(const std::string &func_name);
std::string exec_system(const char *cmd);
std::vector<std::string> resolve_binary_path(const std::string &cmd);
std::vector<std::string> resolve_binary_path(const std::string &cmd, int pid);
std::string path_for_pid_mountns(int pid, const std::string &path);
void cat_file(const char *filename, size_t, std::ostream &);
std::string str_join(const std::vector<std::string> &list,
                     const std::string &delim);
bool is_numeric(const std::string &str);
bool symbol_has_cpp_mangled_signature(const std::string &sym_name);
pid_t parse_pid(const std::string &str);
std::string hex_format_buffer(const char *buf, size_t size);
std::optional<std::string> abs_path(const std::string &rel_path);
bool symbol_has_module(const std::string &symbol);
std::string strip_symbol_module(const std::string &symbol);

// Generate object file section name for a given probe
inline std::string get_section_name_for_probe(
    const std::string &probe_name,
    int index,
    std::optional<int> usdt_location_index = std::nullopt)
{
  auto ret = "s_" + probe_name;

  if (usdt_location_index)
    ret += "_loc" + std::to_string(*usdt_location_index);

  ret += "_" + std::to_string(index);

  return ret;
}

inline std::string get_watchpoint_setup_probe_name(
    const std::string &probe_name)
{
  return probe_name + "_wp_setup";
}

inline std::string get_section_name_for_watchpoint_setup(
    const std::string &probe_name,
    int index)
{
  return get_section_name_for_probe(get_watchpoint_setup_probe_name(probe_name),
                                    index);
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

uint64_t parse_exponent(const char *str);
uint32_t kernel_version(int attempt);

template <typename T>
T reduce_value(const std::vector<uint8_t> &value, int nvalues)
{
  T sum = 0;
  for (int i = 0; i < nvalues; i++)
  {
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
