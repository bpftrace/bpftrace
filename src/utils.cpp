#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <glob.h>
#include <limits>
#include <link.h>
#include <map>
#include <memory>
#include <regex>
#include <sstream>
#include <string>
#include <sys/auxv.h>
#include <sys/stat.h>
#include <tuple>
#include <unistd.h>

#include "bpftrace.h"
#include "log.h"
#include "probe_matcher.h"
#include "utils.h"
#include <bcc/bcc_elf.h>
#include <bcc/bcc_syms.h>
#include <bcc/bcc_usdt.h>
#include <elf.h>

#include <linux/version.h>

#if __has_include(<filesystem>)
#include <filesystem>
namespace std_filesystem = std::filesystem;
#elif __has_include(<experimental/filesystem>)
#include <experimental/filesystem>
namespace std_filesystem = std::experimental::filesystem;
#else
#error "neither <filesystem> nor <experimental/filesystem> are present"
#endif

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

std::string get_pid_exe(const std::string &pid)
{
  std::error_code ec;
  std_filesystem::path proc_path{ "/proc" };
  proc_path /= pid;
  proc_path /= "exe";

  if (!std_filesystem::exists(proc_path, ec) ||
      !std_filesystem::is_symlink(proc_path, ec))
    return "";

  return std_filesystem::read_symlink(proc_path).string();
}

std::string get_pid_exe(pid_t pid)
{
  return get_pid_exe(std::to_string(pid));
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
  std::error_code ec;
  std_filesystem::path buf{ path };
  return std_filesystem::is_directory(buf, ec);
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
    std::error_code ec;
    std_filesystem::path path_prefix{ "/tmp" };
    std_filesystem::path path_kheaders{ "/sys/kernel/kheaders.tar.xz" };
    if (const char* tmpdir = ::getenv("TMPDIR")) {
      path_prefix = tmpdir;
    }
    path_prefix /= "kheaders-";
    std_filesystem::path shared_path{ path_prefix.string() + utsname.release };

    if (std_filesystem::exists(shared_path, ec))
    {
      // already unpacked
      return shared_path.string();
    }

    if (!std_filesystem::exists(path_kheaders, ec))
    {
      StderrSilencer silencer;
      silencer.silence();

      FILE* modprobe = ::popen("modprobe kheaders", "w");
      if (modprobe == nullptr || pclose(modprobe) != 0) {
        return "";
      }

      if (!std_filesystem::exists(path_kheaders, ec))
      {
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
std::tuple<std::string, std::string> get_kernel_dirs(
    const struct utsname &utsname,
    bool unpack_kheaders)
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
  if (ksrc.empty() && kobj.empty())
  {
    if (unpack_kheaders)
    {
      const auto kheaders_tar_xz_path = unpack_kheaders_tar_xz(utsname);
      if (kheaders_tar_xz_path.size() > 0)
        return std::make_tuple(kheaders_tar_xz_path, kheaders_tar_xz_path);
    }
    return std::make_tuple("", "");
  }
  if (ksrc.empty())
  {
    ksrc = kobj;
  }
  else if (kobj.empty())
  {
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
  if (pid <= 0)
    return false;

  std::error_code ec;
  std_filesystem::path self_path{ "/proc/self/ns/mnt" };
  std_filesystem::path target_path{ "/proc" };
  target_path /= std::to_string(pid);
  target_path /= "ns/mnt";

  if (!std_filesystem::exists(self_path, ec))
  {
    throw MountNSException(
        "Failed to compare mount ns with PID " + std::to_string(pid) +
        ". The error was open (/proc/self/ns/mnt): " + ec.message());
  }

  if (!std_filesystem::exists(target_path, ec))
  {
    throw MountNSException(
        "Failed to compare mount ns with PID " + std::to_string(pid) +
        ". The error was open (/proc/<pid>/ns/mnt): " + ec.message());
  }

  bool result = !std_filesystem::equivalent(self_path, target_path, ec);

  if (ec)
  {
    throw MountNSException("Failed to compare mount ns with PID " +
                           std::to_string(pid) +
                           ". The error was (fstat): " + ec.message());
  }

  return result;
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
#ifdef FUZZ
  return {};
#else
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
  {
    if (symbol_has_module(line))
      result.insert(strip_symbol_module(line));
    else
      result.insert(line);
  }
  return result;
#endif
}

uint64_t parse_exponent(const char *str)
{
  char *e_offset;
  auto base = strtoll(str, &e_offset, 10);

  if (*e_offset != 'e')
    return base;

  auto exp = strtoll(e_offset + 1, nullptr, 10);
  auto num = base * std::pow(10, exp);
  uint64_t max = std::numeric_limits<uint64_t>::max();
  if (num > (double)max)
    throw std::runtime_error(std::string(str) + " is too big for uint64_t");
  return num;
}

/**
 * Search for LINUX_VERSION_CODE in the vDSO, returning 0 if it can't be found.
 */
static uint32_t _find_version_note(unsigned long base)
{
  auto ehdr = reinterpret_cast<const ElfW(Ehdr) *>(base);

  for (int i = 0; i < ehdr->e_shnum; i++)
  {
    auto shdr = reinterpret_cast<const ElfW(Shdr) *>(base + ehdr->e_shoff +
                                                     (i * ehdr->e_shentsize));

    if (shdr->sh_type == SHT_NOTE)
    {
      auto ptr = reinterpret_cast<const char *>(base + shdr->sh_offset);
      auto end = ptr + shdr->sh_size;

      while (ptr < end)
      {
        auto nhdr = reinterpret_cast<const ElfW(Nhdr) *>(ptr);
        ptr += sizeof *nhdr;

        auto name = ptr;
        ptr += (nhdr->n_namesz + sizeof(ElfW(Word)) - 1) & -sizeof(ElfW(Word));

        auto desc = ptr;
        ptr += (nhdr->n_descsz + sizeof(ElfW(Word)) - 1) & -sizeof(ElfW(Word));

        if ((nhdr->n_namesz > 5 && !memcmp(name, "Linux", 5)) &&
            nhdr->n_descsz == 4 && !nhdr->n_type)
          return *reinterpret_cast<const uint32_t *>(desc);
      }
    }
  }

  return 0;
}

static uint32_t kernel_version_from_vdso(void)
{
  // Fetch LINUX_VERSION_CODE from the vDSO .note section, falling back on
  // the build-time constant if unavailable. This always matches the
  // running kernel, but is not supported on arm32.
  unsigned code = 0;
  unsigned long base = getauxval(AT_SYSINFO_EHDR);
  if (base && !memcmp(reinterpret_cast<void *>(base), ELFMAG, 4))
    code = _find_version_note(base);
  if (!code)
    code = LINUX_VERSION_CODE;
  return code;
}

static uint32_t kernel_version_from_uts(void)
{
  struct utsname utsname;
  if (uname(&utsname) < 0)
    return 0;
  unsigned x, y, z;
  if (sscanf(utsname.release, "%u.%u.%u", &x, &y, &z) != 3)
    return 0;
  return KERNEL_VERSION(x, y, z);
}

static uint32_t kernel_version_from_khdr(void)
{
  // Try to get the definition of LINUX_VERSION_CODE at runtime.
  std::ifstream linux_version_header{ "/usr/include/linux/version.h" };
  const std::string content{ std::istreambuf_iterator<char>(
                                 linux_version_header),
                             std::istreambuf_iterator<char>() };
  const std::regex regex{ "#define\\s+LINUX_VERSION_CODE\\s+(\\d+)" };
  std::smatch match;

  if (std::regex_search(content.begin(), content.end(), match, regex))
    return static_cast<unsigned>(std::stoi(match[1]));

  return 0;
}

/**
 * Find a LINUX_VERSION_CODE matching the host kernel. The build-time constant
 * may not match if bpftrace is compiled on a different Linux version than it's
 * used on, e.g. if built with Docker.
 */
uint32_t kernel_version(int attempt)
{
  static std::optional<uint32_t> a0, a1, a2;
  switch (attempt)
  {
    case 0:
    {
      if (!a0)
        a0 = kernel_version_from_vdso();
      return *a0;
    }
    case 1:
    {
      if (!a1)
        a1 = kernel_version_from_uts();
      return *a1;
    }
    case 2:
    {
      if (!a2)
        a2 = kernel_version_from_khdr();
      return *a2;
    }
    default:
      throw std::runtime_error("BUG: kernel_version(): Invalid attempt: " +
                               std::to_string(attempt));
  }
}

std::optional<std::string> abs_path(const std::string &rel_path)
{
  // filesystem::canonical does not work very well with /proc/<pid>/root paths
  // of processes in a different mount namespace (than the one bpftrace is
  // running in), failing during canonicalization. See iovisor:bpftrace#1595
  static auto re = std::regex("^/proc/\\d+/root/.*");
  if (!std::regex_match(rel_path, re))
  {
    try
    {
      auto p = std_filesystem::path(rel_path);
      return std_filesystem::canonical(std_filesystem::absolute(p)).string();
    }
    catch (std_filesystem::filesystem_error &)
    {
      return {};
    }
  }
  else
  {
    return rel_path;
  }
}

int64_t min_value(const std::vector<uint8_t> &value, int nvalues)
{
  int64_t val, max = 0, retval;
  for (int i = 0; i < nvalues; i++)
  {
    val = read_data<int64_t>(value.data() + i * sizeof(int64_t));
    if (val > max)
      max = val;
  }

  /*
   * This is a hack really until the code generation for the min() function
   * is sorted out. The way it is currently implemented doesn't allow >
   * 32 bit quantities and also means we have to do gymnastics with the return
   * value owing to the way it is stored (i.e., 0xffffffff - val).
   */
  if (max == 0) /* If we have applied the zero() function */
    retval = max;
  else if ((0xffffffff - max) <= 0) /* A negative 32 bit value */
    retval = 0 - (max - 0xffffffff);
  else
    retval = 0xffffffff - max; /* A positive 32 bit value */

  return retval;
}

uint64_t max_value(const std::vector<uint8_t> &value, int nvalues)
{
  uint64_t val, max = 0;
  for (int i = 0; i < nvalues; i++)
  {
    val = read_data<uint64_t>(value.data() + i * sizeof(uint64_t));
    if (val > max)
      max = val;
  }
  return max;
}

bool symbol_has_module(const std::string &symbol)
{
  return !symbol.empty() && symbol[symbol.size() - 1] == ']';
}

std::string strip_symbol_module(const std::string &symbol)
{
  size_t idx = symbol.rfind(" [");
  return idx != std::string::npos ? symbol.substr(0, idx) : symbol;
}

} // namespace bpftrace
