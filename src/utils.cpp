#include <cmath>
#include <cstring>

#include <algorithm>
#include <array>
#include <fcntl.h>
#include <fstream>
#include <glob.h>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <tuple>
#include <unistd.h>

#include "list.h"
#include "log.h"
#include "utils.h"
#include <bcc/bcc_elf.h>

namespace {

std::vector<int> read_cpu_range(std::string path)
{
  std::ifstream cpus_range_stream { path };
  std::vector<int> cpus;
  std::string cpu_range;

  while (std::getline(cpus_range_stream, cpu_range, ',')) {
    std::size_t rangeop = cpu_range.find('-');
    if (rangeop == std::string::npos) {
      cpus.push_back(std::stoi(cpu_range));
    }
    else {
      int start = std::stoi(cpu_range.substr(0, rangeop));
      int end = std::stoi(cpu_range.substr(rangeop + 1));
      for (int i = start; i <= end; i++)
        cpus.push_back(i);
    }
  }
  return cpus;
}

std::vector<std::string> expand_wildcard_path(const std::string& path)
{
  glob_t glob_result;
  memset(&glob_result, 0, sizeof(glob_result));

  if (glob(path.c_str(), GLOB_NOCHECK, nullptr, &glob_result)) {
    globfree(&glob_result);
    throw std::runtime_error("glob() failed");
  }

  std::vector<std::string> matching_paths;
  for (size_t i = 0; i < glob_result.gl_pathc; ++i) {
    matching_paths.push_back(std::string(glob_result.gl_pathv[i]));
  }

  globfree(&glob_result);
  return matching_paths;
}

std::vector<std::string> expand_wildcard_paths(const std::vector<std::string>& paths)
{
  std::vector<std::string> expanded_paths;
  for (const auto& p : paths)
  {
    auto ep = expand_wildcard_path(p);
    expanded_paths.insert(expanded_paths.end(), ep.begin(), ep.end());
  }
  return expanded_paths;
}

} // namespace

namespace bpftrace {

//'borrowed' from libbpf's bpf_core_find_kernel_btf
// from Andrii Nakryiko
const struct vmlinux_location vmlinux_locs[] = {
  { "/sys/kernel/btf/vmlinux", true },
  { "/boot/vmlinux-%1$s", false },
  { "/lib/modules/%1$s/vmlinux-%1$s", false },
  { "/lib/modules/%1$s/build/vmlinux", false },
  { "/usr/lib/modules/%1$s/kernel/vmlinux", false },
  { "/usr/lib/debug/boot/vmlinux-%1$s", false },
  { "/usr/lib/debug/boot/vmlinux-%1$s.debug", false },
  { "/usr/lib/debug/lib/modules/%1$s/vmlinux", false },
  { nullptr, false },
};

static bool pid_in_different_mountns(int pid);
static std::vector<std::string>
resolve_binary_path(const std::string &cmd, const char *env_paths, int pid);

void StdioSilencer::silence()
{
  fflush(ofile);
  int fd = fileno(ofile);
  old_stdio_ = dup(fd);
  int new_stdio_ = open("/dev/null", O_WRONLY);
  dup2(new_stdio_, fd);
  close(new_stdio_);
}

StdioSilencer::~StdioSilencer()
{
  if (old_stdio_ != -1)
  {
    fflush(ofile);
    int fd = fileno(ofile);
    dup2(old_stdio_, fd);
    close(old_stdio_);
    old_stdio_ = -1;
  }
}

bool get_uint64_env_var(const std::string &str, uint64_t &dest)
{
  if (const char* env_p = std::getenv(str.c_str()))
  {
    std::istringstream stringstream(env_p);
    if (!(stringstream >> dest))
    {
      LOG(ERROR) << "Env var '" << str
                 << "' did not contain a valid uint64_t, or was zero-valued.";
      return false;
    }
  }
  return true;
}

std::string get_pid_exe(pid_t pid)
{
  char proc_path[512];
  char exe_path[4096];
  int res;

  sprintf(proc_path, "/proc/%d/exe", pid);
  res = readlink(proc_path, exe_path, sizeof(exe_path));
  if (res == -1)
    return "";
  if (res >= static_cast<int>(sizeof(exe_path))) {
    throw std::runtime_error("executable path exceeded maximum supported size of 4096 characters");
  }
  exe_path[res] = '\0';
  return std::string(exe_path);
}

bool has_wildcard(const std::string &str)
{
  return str.find("*") != std::string::npos ||
         (str.find("[") != std::string::npos &&
          str.find("]") != std::string::npos);
}

std::vector<std::string> split_string(const std::string &str,
                                      char delimiter,
                                      bool remove_empty)
{
  std::vector<std::string> elems;
  std::stringstream ss(str);
  std::string value;
  while(std::getline(ss, value, delimiter)) {
    if (remove_empty && value.empty())
      continue;

    elems.push_back(value);
  }
  return elems;
}

/// Erase prefix up to the first colon (:) from str and return the prefix
std::string erase_prefix(std::string &str)
{
  std::string prefix = str.substr(0, str.find(':'));
  str.erase(0, prefix.length() + 1);
  return prefix;
}

bool wildcard_match(const std::string &str, std::vector<std::string> &tokens, bool start_wildcard, bool end_wildcard) {
  size_t next = 0;

  if (!start_wildcard)
    if (str.find(tokens[0], next) != next)
      return false;

  for (std::string token : tokens) {
    size_t found = str.find(token, next);
    if (found == std::string::npos)
      return false;

    next = found + token.length();
  }

  if (!end_wildcard)
    if (str.length() != next)
      return false;

  return true;
}

std::vector<int> get_online_cpus()
{
  return read_cpu_range("/sys/devices/system/cpu/online");
}

std::vector<int> get_possible_cpus()
{
  return read_cpu_range("/sys/devices/system/cpu/possible");
}

std::vector<std::string> get_kernel_cflags(
    const char* uname_machine,
    const std::string& ksrc,
    const std::string& kobj)
{
  std::vector<std::string> cflags;
  std::string arch = uname_machine;
  const char *archenv;

  if (!strncmp(uname_machine, "x86_64", 6)) {
    arch = "x86";
  } else if (uname_machine[0] == 'i' && !strncmp(&uname_machine[2], "86", 2)) {
    arch = "x86";
  } else if (!strncmp(uname_machine, "arm", 3)) {
    arch = "arm";
  } else if (!strncmp(uname_machine, "sa110", 5)) {
    arch = "arm";
  } else if (!strncmp(uname_machine, "s390x", 5)) {
    arch = "s390";
  } else if (!strncmp(uname_machine, "parisc64", 8)) {
    arch = "parisc";
  } else if (!strncmp(uname_machine, "ppc", 3)) {
    arch = "powerpc";
  } else if (!strncmp(uname_machine, "mips", 4)) {
    arch = "mips";
  } else if (!strncmp(uname_machine, "sh", 2)) {
    arch = "sh";
  } else if (!strncmp(uname_machine, "aarch64", 7)) {
    arch = "arm64";
  }

  // If ARCH env is defined, use it over uname
  archenv = getenv("ARCH");
  if (archenv)
    arch = std::string(archenv);

  cflags.push_back("-nostdinc");
  cflags.push_back("-isystem");
  cflags.push_back("/virtual/lib/clang/include");

  // see linux/Makefile for $(LINUXINCLUDE) + $(USERINCLUDE)
  cflags.push_back("-I" + ksrc + "/arch/"+arch+"/include");
  cflags.push_back("-I" + kobj + "/arch/"+arch+"/include/generated");
  cflags.push_back("-I" + ksrc + "/include");
  cflags.push_back("-I" + kobj + "/include");
  cflags.push_back("-I" + ksrc + "/arch/"+arch+"/include/uapi");
  cflags.push_back("-I" + kobj + "/arch/"+arch+"/include/generated/uapi");
  cflags.push_back("-I" + ksrc + "/include/uapi");
  cflags.push_back("-I" + kobj + "/include/generated/uapi");

  cflags.push_back("-include");
  cflags.push_back(ksrc + "/include/linux/kconfig.h");
  cflags.push_back("-D__KERNEL__");
  cflags.push_back("-D__BPF_TRACING__");
  cflags.push_back("-D__HAVE_BUILTIN_BSWAP16__");
  cflags.push_back("-D__HAVE_BUILTIN_BSWAP32__");
  cflags.push_back("-D__HAVE_BUILTIN_BSWAP64__");
  cflags.push_back("-DKBUILD_MODNAME=\"bpftrace\"");

  // If ARCH env variable is set, pass this along.
  if (archenv)
    cflags.push_back("-D__TARGET_ARCH_" + arch);

  return cflags;
}

bool is_dir(const std::string& path)
{
  struct stat buf;

  if (::stat(path.c_str(), &buf) < 0)
    return false;

  return S_ISDIR(buf.st_mode);
}

namespace {
  struct KernelHeaderTmpDir {
    KernelHeaderTmpDir(const std::string& prefix) : path{prefix + "XXXXXX"}
    {
      if (::mkdtemp(&path[0]) == nullptr) {
        throw std::runtime_error("creating temporary path for kheaders.tar.xz failed");
      }
    }

    ~KernelHeaderTmpDir()
    {
      if (path.size() > 0) {
        // move_to either did not succeed or did not run, so clean up after ourselves
        exec_system(("rm -rf " + path).c_str());
      }
    }

    void move_to(const std::string& new_path)
    {
      int err = ::rename(path.c_str(), new_path.c_str());
      if (err == 0) {
        path = "";
      }
    }

    std::string path;
  };

  std::string unpack_kheaders_tar_xz(const struct utsname& utsname)
  {
    std::string path_prefix{"/tmp"};
    if (const char* tmpdir = ::getenv("TMPDIR")) {
      path_prefix = tmpdir;
    }
    path_prefix += "/kheaders-";
    std::string shared_path{path_prefix + utsname.release};

    struct stat stat_buf;

    if (::stat(shared_path.c_str(), &stat_buf) == 0) {
      // already unpacked
      return shared_path;
    }

    if (::stat("/sys/kernel/kheaders.tar.xz", &stat_buf) != 0) {
      StderrSilencer silencer;
      silencer.silence();

      FILE* modprobe = ::popen("modprobe kheaders", "w");
      if (modprobe == nullptr || pclose(modprobe) != 0) {
        return "";
      }

      if (::stat("/sys/kernel/kheaders.tar.xz", &stat_buf) != 0) {
        return "";
      }
    }

    KernelHeaderTmpDir tmpdir{path_prefix};

    FILE* tar = ::popen(("tar xf /sys/kernel/kheaders.tar.xz -C " + tmpdir.path).c_str(), "w");
    if (!tar) {
      return "";
    }

    int rc = ::pclose(tar);
    if (rc == 0) {
      tmpdir.move_to(shared_path);
      return shared_path;
    }

    return "";
  }
} // namespace

// get_kernel_dirs returns {ksrc, kobj} - directories for pristine and
// generated kernel sources.
//
// When the kernel was built in its source tree ksrc == kobj, however when
// the kernel was build in a different directory than its source, ksrc != kobj.
//
// A notable example is Debian, which places pristine kernel headers in
//
//   /lib/modules/`uname -r`/source/
//
// and generated kernel headers in
//
//   /lib/modules/`uname -r`/build/
//
// {"", ""} is returned if no trace of kernel headers was found at all.
// Both ksrc and kobj are guaranteed to be != "", if at least some trace of kernel sources was found.
std::tuple<std::string, std::string> get_kernel_dirs(const struct utsname& utsname)
{
#ifdef KERNEL_HEADERS_DIR
  return {KERNEL_HEADERS_DIR, KERNEL_HEADERS_DIR};
#endif

  const char *kpath_env = ::getenv("BPFTRACE_KERNEL_SOURCE");
  if (kpath_env)
    return std::make_tuple(kpath_env, kpath_env);

  std::string kdir = std::string("/lib/modules/") + utsname.release;
  auto ksrc = kdir + "/source";
  auto kobj = kdir + "/build";

  // if one of source/ or build/ is not present - try to use the other one for both.
  if (!is_dir(ksrc)) {
    ksrc = "";
  }
  if (!is_dir(kobj)) {
    kobj = "";
  }
  if (ksrc == "" && kobj == "") {
    const auto kheaders_tar_xz_path = unpack_kheaders_tar_xz(utsname);
    if (kheaders_tar_xz_path.size() > 0) {
      return std::make_tuple(kheaders_tar_xz_path, kheaders_tar_xz_path);
    }
    return std::make_tuple("", "");
  }
  if (ksrc == "") {
    ksrc = kobj;
  }
  else if (kobj == "") {
    kobj = ksrc;
  }

  return std::make_tuple(ksrc, kobj);
}

const std::string &is_deprecated(const std::string &str)
{

  std::vector<DeprecatedName>::iterator item;

  for (item = DEPRECATED_LIST.begin(); item != DEPRECATED_LIST.end(); item++)
  {
    if (str == item->old_name)
    {
      if (item->show_warning)
      {
        LOG(WARNING) << item->old_name
                     << " is deprecated and will be removed in the future. Use "
                     << item->new_name << " instead.";
        item->show_warning = false;
      }

      return item->new_name;
    }
  }

  return str;
}

bool is_unsafe_func(const std::string &func_name)
{
  return std::any_of(
      UNSAFE_BUILTIN_FUNCS.begin(),
      UNSAFE_BUILTIN_FUNCS.end(),
      [&](const auto& cand) {
        return func_name == cand;
      });
}

bool is_compile_time_func(const std::string &func_name)
{
  return std::any_of(COMPILE_TIME_FUNCS.begin(),
                     COMPILE_TIME_FUNCS.end(),
                     [&](const auto &cand) { return func_name == cand; });
}

std::string exec_system(const char* cmd)
{
  std::array<char, 128> buffer;
  std::string result;
  std::shared_ptr<FILE> pipe(popen(cmd, "r"), pclose);
  if (!pipe) throw std::runtime_error("popen() failed!");
  while (!feof(pipe.get())) {
    if (fgets(buffer.data(), 128, pipe.get()) != nullptr)
      result += buffer.data();
  }
  return result;
}

/*
Original resolve_binary_path API defaulting to bpftrace's mount namespace
*/
std::vector<std::string> resolve_binary_path(const std::string& cmd)
{
  const char *env_paths = getenv("PATH");
  return resolve_binary_path(cmd, env_paths, -1);
}

/*
If a pid is specified, the binary path is taken relative to its own PATH if
it is in a different mount namespace. Otherwise, the path is resolved relative
to the local PATH env var for bpftrace's own mount namespace if it is set
*/
std::vector<std::string> resolve_binary_path(const std::string &cmd, int pid)
{
  std::string env_paths = "";
  std::ostringstream pid_environ_path;

  if (pid > 0 && pid_in_different_mountns(pid))
  {
    pid_environ_path << "/proc/" << pid << "/environ";
    std::ifstream environ(pid_environ_path.str());

    if (environ)
    {
      std::string env_var;
      std::string pathstr = ("PATH=");
      while (std::getline(environ, env_var, '\0'))
      {
        if (env_var.find(pathstr) != std::string::npos)
        {
          env_paths = env_var.substr(pathstr.length());
          break;
        }
      }
    }
    return resolve_binary_path(cmd, env_paths.c_str(), pid);
  }
  else
  {
    return resolve_binary_path(cmd, getenv("PATH"), pid);
  }
}

/*
Private interface to resolve_binary_path, used for the exposed variants above,
allowing for a PID whose mount namespace should be optionally considered.
*/
static std::vector<std::string>
resolve_binary_path(const std::string &cmd, const char *env_paths, int pid)
{
  std::vector<std::string> candidate_paths = { cmd };

  if (env_paths != nullptr && cmd.find("/") == std::string::npos)
    for (const auto& path : split_string(env_paths, ':'))
      candidate_paths.push_back(path + "/" + cmd);

  if (cmd.find("*") != std::string::npos)
    candidate_paths = ::expand_wildcard_paths(candidate_paths);

  std::vector<std::string> valid_executable_paths;
  for (const auto &path : candidate_paths)
  {
    std::string rel_path;
    if (pid > 0 && pid_in_different_mountns(pid))
      rel_path = path_for_pid_mountns(pid, path);
    else
      rel_path = path;
    if (bcc_elf_is_exe(rel_path.c_str()) ||
        bcc_elf_is_shared_obj(rel_path.c_str()))
      valid_executable_paths.push_back(rel_path);
  }

  return valid_executable_paths;
}

std::string path_for_pid_mountns(int pid, const std::string &path)
{
  std::ostringstream pid_relative_path;
  char pid_root[64];

  snprintf(pid_root, sizeof(pid_root), "/proc/%d/root", pid);

  if (path.find(pid_root) != 0)
  {
    std::string sep = (path.length() >= 1 && path.at(0) == '/') ? "" : "/";
    pid_relative_path << pid_root << sep << path;
  }
  else
  {
    // The path is already relative to the pid's root
    pid_relative_path << path;
  }
  return pid_relative_path.str();
}

/*
Determines if the target process is in a different mount namespace from
bpftrace.

If a process is in a different mount namespace (eg, container) it is very
likely that any references to local paths will not be valid, and that paths
need to be made relative to the PID.

If an invalid PID is specified or doesn't exist, it returns false.
True is only returned if the namespace of the target process could be read and
it doesn't match that of bpftrace. If there was an error reading either mount
namespace, it will throw an exception
*/
static bool pid_in_different_mountns(int pid)
{

  struct stat self_stat, target_stat;
  int self_fd = -1, target_fd = -1;
  std::stringstream errmsg;
  char buf[64];

  if (pid <= 0)
    return false;

  if ((size_t)snprintf(buf, sizeof(buf), "/proc/%d/ns/mnt", pid) >= sizeof(buf))
  {
    errmsg << "Reading mountNS would overflow buffer.";
    goto error;
  }

  self_fd = open("/proc/self/ns/mnt", O_RDONLY);
  if (self_fd < 0)
  {
    errmsg << "open(/proc/self/ns/mnt): " << strerror(errno);
    goto error;
  }

  target_fd = open(buf, O_RDONLY);
  if (target_fd < 0)
  {
    errmsg << "open(/proc/<pid>/ns/mnt): " << strerror(errno);
    goto error;
  }

  if (fstat(self_fd, &self_stat))
  {
    errmsg << "fstat(self_fd): " << strerror(errno);
    goto error;
  }

  if (fstat(target_fd, &target_stat))
  {
    errmsg << "fstat(target_fd)" << strerror(errno);
    goto error;
  }

  close(self_fd);
  close(target_fd);
  return self_stat.st_ino != target_stat.st_ino;

error:
  if (self_fd >= 0)
    close(self_fd);
  if (target_fd >= 0)
    close(target_fd);

  throw MountNSException("Failed to compare mount ns with PID " +
                         std::to_string(pid) + ". " + "The error was " +
                         errmsg.str());

  return false;
}

void cat_file(const char *filename, size_t max_bytes, std::ostream &out)
{
  std::ifstream file(filename);
  const size_t BUFSIZE = 4096;

  if (file.fail()){
    LOG(ERROR) << "failed to open file '" << filename
               << "': " << strerror(errno);
    return;
  }

  char buf[BUFSIZE];
  size_t bytes_read = 0;
  // Read the file batches to avoid allocating a potentially
  // massive buffer.
  while (bytes_read < max_bytes) {
    size_t size = std::min(BUFSIZE, max_bytes - bytes_read);
    file.read(buf, size);
    out.write(buf, file.gcount());
    if (file.eof()) {
      return;
    }
    if (file.fail()) {
      LOG(ERROR) << "failed to open file '" << filename
                 << "': " << strerror(errno);
      return;
    }
    bytes_read += file.gcount();
  }
}

std::string str_join(const std::vector<std::string> &list, const std::string &delim)
{
  std::string str;
  bool first = true;
  for (const auto &elem : list)
  {
    if (first)
      first = false;
    else
      str += delim;

    str += elem;
  }
  return str;
}

bool is_numeric(const std::string &s)
{
  std::size_t idx;
  try
  {
    std::stoll(s, &idx, 0);
  }
  catch (...)
  {
    return false;
  }
  return idx == s.size();
}

bool symbol_has_cpp_mangled_signature(const std::string &sym_name)
{
  if (!sym_name.rfind("_Z", 0) || !sym_name.rfind("____Z", 0))
    return true;
  else
    return false;
}

pid_t parse_pid(const std::string &str)
{
  try
  {
    constexpr ssize_t pid_max = 4 * 1024 * 1024;
    std::size_t idx = 0;
    auto pid = std::stol(str, &idx, 10);
    // Detect cases like `13ABC`
    if (idx < str.size())
      throw InvalidPIDException(str, "is not a valid decimal number");
    if (pid < 1 || pid > pid_max)
      throw InvalidPIDException(str,
                                "out of valid pid range [1," +
                                    std::to_string(pid_max) + "]");
    return pid;
  }
  catch (const std::out_of_range &e)
  {
    throw InvalidPIDException(str, "outside of integer range");
  }
  catch (const std::invalid_argument &e)
  {
    throw InvalidPIDException(str, "is not a valid decimal number");
  }
}

std::string hex_format_buffer(const char *buf, size_t size)
{
  // Allow enough space for every byte to be sanitized in the form "\x00"
  char s[size * 4 + 1];

  size_t offset = 0;
  for (size_t i = 0; i < size; i++)
    if (buf[i] >= 32 && buf[i] <= 126)
      offset += sprintf(s + offset, "%c", ((const uint8_t *)buf)[i]);
    else
      offset += sprintf(s + offset, "\\x%02x", ((const uint8_t *)buf)[i]);

  s[offset] = '\0';

  return std::string(s);
}

std::unordered_set<std::string> get_traceable_funcs()
{
  // Try to get the list of functions from BPFTRACE_AVAILABLE_FUNCTIONS_TEST env
  const char *path = std::getenv("BPFTRACE_AVAILABLE_FUNCTIONS_TEST");

  // Use kprobe list as default
  if (!path)
    path = kprobe_path.c_str();

  std::ifstream available_funs(path);
  if (available_funs.fail())
  {
    if (bt_debug != DebugLevel::kNone)
    {
      std::cerr << "Error while reading traceable functions from "
                << kprobe_path << ": " << strerror(errno);
    }
    return {};
  }

  std::unordered_set<std::string> result;
  std::string line;
  while (std::getline(available_funs, line))
    result.insert(line);
  return result;
}

uint64_t parse_exponent(const char *str)
{
  char *e_offset;
  auto base = strtoll(str, &e_offset, 10);

  if (*e_offset != 'e')
    return base;

  auto exp = strtoll(e_offset + 1, nullptr, 10);
  auto num = base * std::pow(10, exp);
  return num;
}

} // namespace bpftrace
