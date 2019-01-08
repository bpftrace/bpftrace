#include "utils.h"

#include <string.h>

#include <fstream>

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
    const std::string& kdir)
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

  cflags.push_back("-I" + kdir + "/arch/"+arch+"/include");
  cflags.push_back("-I" + kdir + "/arch/"+arch+"/include/generated/uapi");
  cflags.push_back("-I" + kdir + "/arch/"+arch+"/include/generated");
  cflags.push_back("-I" + kdir + "/include");
  cflags.push_back("-I" + kdir + "/./arch/"+arch+"/include/uapi");
  cflags.push_back("-I" + kdir + "/arch/"+arch+"/include/generated/uapi");
  cflags.push_back("-I" + kdir + "/include/uapi");
  cflags.push_back("-I" + kdir + "/include/generated");
  cflags.push_back("-I" + kdir + "/include/generated/uapi");

  cflags.push_back("-include");
  cflags.push_back(kdir + "/include/linux/kconfig.h");
  cflags.push_back("-D__KERNEL__");
  cflags.push_back("-D__HAVE_BUILTIN_BSWAP16__");
  cflags.push_back("-D__HAVE_BUILTIN_BSWAP32__");
  cflags.push_back("-D__HAVE_BUILTIN_BSWAP64__");

  // If ARCH env variable is set, pass this along.
  if (archenv)
	cflags.push_back("-D__TARGET_ARCH_" + arch);

  return cflags;
}

} // namespace bpftrace
