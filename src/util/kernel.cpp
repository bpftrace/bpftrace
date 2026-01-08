#include <algorithm>
#include <bcc/bcc_elf.h>
#include <bcc/bcc_syms.h>
#include <cstring>
#include <elf.h>
#include <fcntl.h>
#include <fstream>
#include <gelf.h>
#include <glob.h>
#include <libelf.h>
#include <link.h>
#include <linux/limits.h>
#include <linux/version.h>
#include <regex>
#include <sys/auxv.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <zlib.h>

#include "btf.h"
#include "debugfs/debugfs.h"
#include "log.h"
#include "tracefs/tracefs.h"
#include "util/kernel.h"
#include "util/paths.h"
#include "util/symbols.h"

namespace bpftrace::util {

// Search for LINUX_VERSION_CODE in the vDSO, returning 0 if it can't be found.
static uint32_t _find_version_note(unsigned long base)
{
  const auto *ehdr = reinterpret_cast<const ElfW(Ehdr) *>(base);

  for (Elf64_Half i = 0; i < ehdr->e_shnum; i++) {
    const auto *shdr = reinterpret_cast<const ElfW(Shdr) *>(
        base + ehdr->e_shoff + (i * ehdr->e_shentsize));

    if (shdr->sh_type == SHT_NOTE) {
      const auto *ptr = reinterpret_cast<const char *>(base + shdr->sh_offset);
      const auto *end = ptr + shdr->sh_size;

      while (ptr < end) {
        const auto *nhdr = reinterpret_cast<const ElfW(Nhdr) *>(ptr);
        ptr += sizeof *nhdr;

        const auto *name = ptr;
        ptr += (nhdr->n_namesz + sizeof(ElfW(Word)) - 1) & -sizeof(ElfW(Word));

        const auto *desc = ptr;
        ptr += (nhdr->n_descsz + sizeof(ElfW(Word)) - 1) & -sizeof(ElfW(Word));

        if ((nhdr->n_namesz > 5 && !memcmp(name, "Linux", 5)) &&
            nhdr->n_descsz == 4 && !nhdr->n_type)
          return *reinterpret_cast<const uint32_t *>(desc);
      }
    }
  }

  return 0;
}

static uint32_t kernel_version_from_vdso()
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

static uint32_t kernel_version_from_uts()
{
  struct utsname utsname;
  if (uname(&utsname) < 0)
    return 0;
  unsigned x, y, z;
  if (sscanf(utsname.release, "%u.%u.%u", &x, &y, &z) != 3)
    return 0;
  return KERNEL_VERSION(x, y, z);
}

static uint32_t kernel_version_from_khdr()
{
  // Try to get the definition of LINUX_VERSION_CODE at runtime.
  std::ifstream linux_version_header{ "/usr/include/linux/version.h" };
  const std::string content{ std::istreambuf_iterator<char>(
                                 linux_version_header),
                             std::istreambuf_iterator<char>() };
  const std::regex regex{ R"(#define\s+LINUX_VERSION_CODE\s+(\d+))" };
  std::smatch match;

  if (std::regex_search(content.begin(), content.end(), match, regex))
    return static_cast<unsigned>(std::stoi(match[1]));

  return 0;
}

// Find a LINUX_VERSION_CODE matching the host kernel. The build-time constant
// may not match if bpftrace is compiled on a different Linux version than it's
// used on, e.g. if built with Docker.
uint32_t kernel_version(KernelVersionMethod method)
{
  static std::optional<uint32_t> a0, a1, a2;
  switch (method) {
    case vDSO: {
      if (!a0)
        a0 = kernel_version_from_vdso();
      return *a0;
    }
    case UTS: {
      if (!a1)
        a1 = kernel_version_from_uts();
      return *a1;
    }
    case File: {
      if (!a2)
        a2 = kernel_version_from_khdr();
      return *a2;
    }
    case None:
      return 0;
  }

  // Unreachable
  return 0;
}

static std::string release = [] {
  struct utsname uts = {};
  assert(uname(&uts) == 0);
  return std::string(uts.release);
}();

struct vmlinux_location {
  std::string path; // full path to the kernel
  bool raw;         // file is either as ELF (false) or raw BTF data (true)
};

//'borrowed' from libbpf's bpf_core_find_kernel_btf
// from Andrii Nakryiko
const struct vmlinux_location vmlinux_locs[] = {
  { .path = "/sys/kernel/btf/vmlinux", .raw = true },
  { .path = "/boot/vmlinux-" + release, .raw = false },
  { .path = "/lib/modules/" + release + "/vmlinux-" + release, .raw = false },
  { .path = "/lib/modules/" + release + "/build/vmlinux", .raw = false },
  { .path = "/usr/lib/modules/" + release + "/kernel/vmlinux", .raw = false },
  { .path = "/usr/lib/debug/boot/vmlinux-" + release, .raw = false },
  { .path = "/usr/lib/debug/boot/vmlinux-" + release + ".debug", .raw = false },
  { .path = "/usr/lib/debug/lib/modules/" + release + "/vmlinux",
    .raw = false },
  {},
};

std::optional<std::string> find_vmlinux(struct vmlinux_location const *locs,
                                        struct symbol *sym)
{
  for (size_t i = 0; !locs[i].path.empty(); ++i) {
    const auto &loc = locs[i];
    if (loc.raw)
      continue; // This file is for BTF. skip

    if (access(loc.path.c_str(), R_OK))
      continue;

    if (sym == nullptr) {
      return loc.path;
    } else {
      bcc_elf_symcb callback = !sym->name.empty() ? sym_name_cb
                                                  : sym_address_cb;
      struct bcc_symbol_option options = {
        .use_debug_file = 0,
        .check_debug_file_crc = 0,
        .lazy_symbolize = 0,
        .use_symbol_type = BCC_SYM_ALL_TYPES ^ (1 << STT_NOTYPE),
      };
      if (bcc_elf_foreach_sym(loc.path.c_str(), callback, &options, sym) ==
          -1) {
        LOG(ERROR) << "Failed to iterate over symbols in " << loc.path;
        continue;
      }

      if (sym->start) {
        LOG(V1) << "vmlinux: using " << loc.path;
        return loc.path;
      }
    }
  }

  return std::nullopt;
}

// find vmlinux file.
// if sym is not null, check vmlinux contains the given symbol information
std::optional<std::string> find_vmlinux(struct symbol *sym)
{
  const char *path = std::getenv("BPFTRACE_VMLINUX");
  if (path != nullptr) {
    struct vmlinux_location locs_env[] = {
      { .path = path, .raw = false },
      {},
    };
    return find_vmlinux(locs_env, sym);
  }
  return find_vmlinux(vmlinux_locs, sym);
}

static bool is_bad_func(std::string &func)
{
  // Certain kernel functions are known to cause system stability issues if
  // traced (but not marked "notrace" in the kernel) so they should be filtered
  // out as the list is built. The list of functions have been taken from the
  // bpf kernel selftests (bpf/prog_tests/kprobe_multi_test.c).
  static const std::unordered_set<std::string> bad_funcs = {
    "arch_cpu_idle", "default_idle", "bpf_dispatcher_xdp_func"
  };

  static const std::vector<std::string> bad_funcs_partial = {
    "__ftrace_invalid_address__", "rcu_"
  };

  if (bad_funcs.contains(func))
    return true;

  return std::ranges::any_of(bad_funcs_partial, [func](const auto &s) {
    return !std::strncmp(func.c_str(), s.c_str(), s.length());
  });
}

FuncsModulesMap parse_traceable_funcs()
{
  // Try to get the list of functions from BPFTRACE_AVAILABLE_FUNCTIONS_TEST env
  const char *path_env = std::getenv("BPFTRACE_AVAILABLE_FUNCTIONS_TEST");
  const std::string kprobe_path = path_env
                                      ? path_env
                                      : tracefs::available_filter_functions();

  std::ifstream available_funs(kprobe_path);
  if (available_funs.fail()) {
    LOG(V1) << "Error while reading traceable functions from " << kprobe_path
            << ": " << strerror(errno);
    return {};
  }

  FuncsModulesMap result;
  std::string line;
  while (std::getline(available_funs, line)) {
    auto func_mod = split_symbol_module(line);
    if (func_mod.second.empty())
      func_mod.second = "vmlinux";

    if (!is_bad_func(func_mod.first))
      result[func_mod.first].insert(func_mod.second);
  }

  // Filter out functions from the kprobe blacklist.
  const std::string kprobes_blacklist_path = debugfs::kprobes_blacklist();
  std::ifstream kprobes_blacklist_funs(kprobes_blacklist_path);
  while (std::getline(kprobes_blacklist_funs, line)) {
    auto addr_func_mod = split_addrrange_symbol_module(line);
    if (result.contains(std::get<1>(addr_func_mod))) {
      result.erase(std::get<1>(addr_func_mod));
    }
  }

  return result;
}

FuncsModulesMap parse_rawtracepoints()
{
  // Using "available_filter_functions" here because they have the correct
  // module for the prefixed raw tracepoints e.g. in "available_events"
  // there is "kvmmmu:check_mmio_spte" but the module is actually "kvm"
  // and shows up as "__probestub_check_mmio_spte [kvm]" in
  // "available_filter_functions"
  const std::string ff_path = tracefs::available_filter_functions();

  std::ifstream available_funs(ff_path);
  if (available_funs.fail()) {
    LOG(V1) << "Error while reading traceable functions from " << ff_path
            << ": " << strerror(errno);
    return {};
  }

  FuncsModulesMap result;
  std::string line;
  while (std::getline(available_funs, line)) {
    auto func_mod = split_symbol_module(line);
    if (func_mod.second.empty())
      func_mod.second = "vmlinux";

    for (const auto &prefix : RT_BTF_PREFIXES) {
      if (func_mod.first.starts_with(prefix)) {
        func_mod.first.erase(0, prefix.length());
        result[func_mod.first].insert(func_mod.second);
        break;
      }
    }
  }

  return result;
}

KConfig::KConfig()
{
  std::vector<std::string> config_locs;

  // Try to get the config from BPFTRACE_KCONFIG_TEST env
  // If not set, use the set of default locations
  const char *path_env = std::getenv("BPFTRACE_KCONFIG_TEST");
  if (path_env)
    config_locs = { std::string(path_env) };
  else {
    struct utsname utsname;
    if (uname(&utsname) < 0)
      return;
    config_locs = {
      "/proc/config.gz",
      "/boot/config-" + std::string(utsname.release),
    };
  }

  for (auto &path : config_locs) {
    // gzopen/gzgets handle both uncompressed and compressed files
    gzFile file = gzopen(path.c_str(), "r");
    if (!file)
      continue;

    char buf[4096];
    while (gzgets(file, buf, sizeof(buf))) {
      std::string option(buf);
      if (option.starts_with("CONFIG_")) {
        // trim trailing '\n'
        if (option[option.length() - 1] == '\n')
          option = option.substr(0, option.length() - 1);

        auto split = option.find("=");
        if (split == std::string::npos)
          continue;

        config.emplace(option.substr(0, split), option.substr(split + 1));
      }
    }
    gzclose(file);
    break;
  }
}

// get_kernel_dirs fills {ksrc, kobj} - directories for pristine and
// generated kernel sources - and returns if they were found.
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
// false is returned if no trace of kernel headers was found at all, with the
// guessed location set anyway for later warning.
//
// Both ksrc and kobj are guaranteed to be != ""
bool get_kernel_dirs(const struct utsname &utsname,
                     std::string &ksrc,
                     std::string &kobj)
{
  ksrc = kobj = std::string(KERNEL_HEADERS_DIR);
  if (!ksrc.empty())
    return true;

  const char *kpath_env = ::getenv("BPFTRACE_KERNEL_SOURCE");
  if (kpath_env) {
    ksrc = std::string(kpath_env);
    const char *kpath_build_env = ::getenv("BPFTRACE_KERNEL_BUILD");
    if (kpath_build_env) {
      kobj = std::string(kpath_build_env);
    } else {
      kobj = ksrc;
    }
    return true;
  }

  std::string kdir = std::string("/lib/modules/") + utsname.release;
  ksrc = kdir + "/source";
  kobj = kdir + "/build";

  // if one of source/ or build/ is not present - try to use the other one for
  // both.
  auto has_ksrc = is_dir(ksrc);
  auto has_kobj = is_dir(kobj);
  if (!has_ksrc && !has_kobj) {
    return false;
  }
  if (!has_ksrc) {
    ksrc = kobj;
  } else if (!has_kobj) {
    kobj = ksrc;
  }

  return true;
}

std::vector<std::string> get_kernel_cflags(const char *uname_machine,
                                           const std::string &ksrc,
                                           const std::string &kobj,
                                           const KConfig &kconfig)
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
  } else if (!strncmp(uname_machine, "loongarch", 9)) {
    arch = "loongarch";
  }

  // If ARCH env is defined, use it over uname
  archenv = getenv("ARCH");
  if (archenv)
    arch = std::string(archenv);

  cflags.emplace_back("-nostdinc");
  cflags.emplace_back("-isystem");
  cflags.emplace_back("/virtual/lib/clang/include");

  // see linux/Makefile for $(LINUXINCLUDE) + $(USERINCLUDE)
  cflags.push_back("-I" + ksrc + "/arch/" + arch + "/include");
  cflags.push_back("-I" + kobj + "/arch/" + arch + "/include/generated");
  cflags.push_back("-I" + ksrc + "/include");
  cflags.push_back("-I" + kobj + "/include");
  cflags.push_back("-I" + ksrc + "/arch/" + arch + "/include/uapi");
  cflags.push_back("-I" + kobj + "/arch/" + arch + "/include/generated/uapi");
  cflags.push_back("-I" + ksrc + "/include/uapi");
  cflags.push_back("-I" + kobj + "/include/generated/uapi");

  cflags.emplace_back("-include");
  cflags.push_back(ksrc + "/include/linux/kconfig.h");
  cflags.emplace_back("-D__KERNEL__");
  cflags.emplace_back("-D__BPF_TRACING__");
  cflags.emplace_back("-D__HAVE_BUILTIN_BSWAP16__");
  cflags.emplace_back("-D__HAVE_BUILTIN_BSWAP32__");
  cflags.emplace_back("-D__HAVE_BUILTIN_BSWAP64__");
  cflags.emplace_back("-DKBUILD_MODNAME=\"bpftrace\"");

  // If ARCH env variable is set, pass this along.
  if (archenv)
    cflags.push_back("-D__TARGET_ARCH_" + arch);

  if (arch == "arm") {
    // Required by several header files in arch/arm/include
    cflags.emplace_back("-D__LINUX_ARM_ARCH__=7");
  }

  if (arch == "arm64") {
    // arm64 defines KASAN_SHADOW_SCALE_SHIFT in a Makefile instead of defining
    // it in a header file. Since we're not executing make, we need to set the
    // value manually (values are taken from arch/arm64/Makefile).
    if (kconfig.has_value("CONFIG_KASAN", "y")) {
      if (kconfig.has_value("CONFIG_KASAN_SW_TAGS", "y"))
        cflags.emplace_back("-DKASAN_SHADOW_SCALE_SHIFT=4");
      else
        cflags.emplace_back("-DKASAN_SHADOW_SCALE_SHIFT=3");
    }
  }

  return cflags;
}

bool is_module_loaded(const std::string &module)
{
  if (module == "vmlinux") {
    return true;
  }

  // This file lists all loaded modules
  std::ifstream modules_file("/proc/modules");

  for (std::string line; std::getline(modules_file, line);) {
    if (line.compare(0, module.size() + 1, module + " ") == 0) {
      modules_file.close();
      return true;
    }
  }

  modules_file.close();
  return false;
}

} // namespace bpftrace::util
