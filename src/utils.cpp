#include <string.h>

#include <algorithm>
#include <array>
#include <map>
#include <string>
#include <tuple>
#include <sstream>
#include <fstream>
#include <memory>
#include <unistd.h>
#include <sys/stat.h>

#include "utils.h"
#include "bcc_usdt.h"

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

} // namespace

namespace bpftrace {

static bool provider_cache_loaded = false;

// Maps all providers of pid to vector of tracepoints on that provider
static std::map<std::string, usdt_probe_list> usdt_provider_cache;

static void usdt_probe_each(struct bcc_usdt *usdt_probe)
{
  usdt_provider_cache[usdt_probe->provider].push_back(std::make_tuple(usdt_probe->bin_path, usdt_probe->provider, usdt_probe->name));
}

usdt_probe_entry USDTHelper::find(
    int pid,
    const std::string &target,
    const std::string &provider,
    const std::string &name)
{

  if (pid > 0)
    read_probes_for_pid(pid);
  else
    read_probes_for_path(target);

  usdt_probe_list probes = usdt_provider_cache[provider];

  auto it = std::find_if(probes.begin(), probes.end(), [&name](const usdt_probe_entry& e) {return std::get<USDT_FNAME_INDEX>(e) == name;});
  if (it != probes.end()) {
    return *it;
  } else {
    return std::make_tuple("", "", "");
  }
}

usdt_probe_list USDTHelper::probes_for_provider(const std::string &provider)
{
  usdt_probe_list probes;

  if(!provider_cache_loaded) {
    std::cerr << "cannot read probes by provider before providers have been loaded by pid or path." << std::endl;
    return probes;
  }

  read_probes_for_pid(0);
  return usdt_provider_cache[provider];
}

usdt_probe_list USDTHelper::probes_for_pid(int pid)
{
  read_probes_for_pid(pid);

  usdt_probe_list probes;
  for (auto const& usdt_probes : usdt_provider_cache)
  {
    probes.insert( probes.end(), usdt_probes.second.begin(), usdt_probes.second.end() );
  }
  return probes;
}

usdt_probe_list USDTHelper::probes_for_path(const std::string &path)
{
  read_probes_for_path(path);

  usdt_probe_list probes;
  for (auto const& usdt_probes : usdt_provider_cache)
  {
    probes.insert( probes.end(), usdt_probes.second.begin(), usdt_probes.second.end() );
  }
  return probes;
}

void USDTHelper::read_probes_for_pid(int pid)
{
  if(provider_cache_loaded)
    return;

  if (pid > 0) {
    void *ctx = bcc_usdt_new_frompid(pid, nullptr);
    if (ctx == nullptr) {
      std::cerr << "failed to initialize usdt context for pid: " << pid << std::endl;
      if (kill(pid, 0) == -1 && errno == ESRCH) {
        std::cerr << "hint: process not running" << std::endl;
      }
      return;
    }
    bcc_usdt_foreach(ctx, usdt_probe_each);
    bcc_usdt_close(ctx);

    provider_cache_loaded = true;
  } else {
    std::cerr << "a pid must be specified to list USDT probes by PID" << std::endl;
  }
}

void USDTHelper::read_probes_for_path(const std::string &path)
{
  if(provider_cache_loaded)
    return;

  void *ctx = bcc_usdt_new_frompath(path.c_str());
  if (ctx == nullptr) {
    std::cerr << "failed to initialize usdt context for path " << path << std::endl;
    return;
  }
  bcc_usdt_foreach(ctx, usdt_probe_each);
  bcc_usdt_close(ctx);

  provider_cache_loaded = true;
}

bool get_uint64_env_var(const std::string &str, uint64_t &dest)
{
  if (const char* env_p = std::getenv(str.c_str()))
  {
    std::istringstream stringstream(env_p);
    if (!(stringstream >> dest))
    {
      std::cerr << "Env var '" << str << "' did not contain a valid uint64_t, or was zero-valued." << std::endl;
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

std::vector<std::string> split_string(const std::string &str, char delimiter) {
  std::vector<std::string> elems;
  std::stringstream ss(str);
  std::string value;
  while(std::getline(ss, value, delimiter)) {
    elems.push_back(value);
  }
  return elems;
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
  cflags.push_back("-DKBUILD_MODNAME='\"bpftrace\"'");

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

std::string is_deprecated(std::string &str)
{

  std::vector<DeprecatedName>::iterator item;

  for (item = DEPRECATED_LIST.begin(); item != DEPRECATED_LIST.end(); item++)
  {
    if (str == item->old_name)
    {
      if (item->show_warning)
      {
        std::cerr << "warning: " << item->old_name << " is deprecated and will be removed in the future. ";
        std::cerr << "Use " << item->new_name << " instead." << std::endl;
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

std::string resolve_binary_path(const std::string& cmd)
{
  std::string query;
  query += "command -v ";
  query += cmd;
  std::string result = exec_system(query.c_str());

  if (result.size())
  {
    // Remove newline at the end
    auto it = result.rfind('\n');
    if (it != std::string::npos)
      result.erase(it);

    return result;
  }
  else
  {
    return cmd;
  }
}

void cat_file(const char *filename, size_t max_bytes, std::ostream &out)
{
  std::ifstream file(filename);
  const size_t BUFSIZE = 4096;

  if (file.fail()){
    std::cerr << "Error opening file '" << filename << "': ";
    std::cerr << strerror(errno) << std::endl;
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
      std::cerr << "Error opening file '" << filename << "': ";
      std::cerr << strerror(errno) << std::endl;
      return;
    }
    bytes_read += file.gcount();
  }
}

std::string str_join(const std::vector<std::string> &list, const std::string &delim)
{
  std::string str;
  int i = 0;
  for (auto &elem : list)
  {
    if (i > 0)
      str += delim;

    str += elem;
    i++;
  }
  return str;
}

bool is_integer(const std::string &str, bool allow_negative)
{
  if (str.empty())
    return false;

  size_t i = 0;
  if (allow_negative && str[0] == '-')
    i++;

  for (; i < str.length(); i++) {
    if (!isdigit(str[i]))
      return false;
  }
  return true;
}

} // namespace bpftrace
