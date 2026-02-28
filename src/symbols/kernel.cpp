#include <algorithm>
#include <bcc/bcc_elf.h>
#include <bcc/bcc_syms.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <cstring>
#include <elf.h>
#include <fcntl.h>
#include <fstream>
#include <gelf.h>
#include <glob.h>
#include <iterator>
#include <libelf.h>
#include <limits>
#include <link.h>
#include <linux/btf.h>
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
#include "scopeguard.h"
#include "symbols/kernel.h"
#include "tracefs/tracefs.h"
#include "util/fd.h"
#include "util/paths.h"
#include "util/strings.h"
#include "util/symbols.h"
#include "util/wildcard.h"

namespace bpftrace::symbols {

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

static std::optional<std::string> find_vmlinux(
    struct vmlinux_location const *locs,
    struct util::symbol *sym)
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
      bcc_elf_symcb callback = !sym->name.empty() ? util::sym_name_cb
                                                  : util::sym_address_cb;
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
std::optional<std::string> find_vmlinux(struct util::symbol *sym)
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

static bool is_bad_func(const std::string &func)
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

static Result<ModuleSet> parse_modules()
{
  std::ifstream modules_file("/proc/modules");
  if (modules_file.fail()) {
    return make_error<SystemError>("Error reading modules from /proc/modules");
  }

  // We have a single pseudo-module for the main kernel binary, which
  // is vmlinux. This is used throughout the codebase to refer to the
  // kernel. For simplicity, we just add it here and everything else
  // just works out, since we also use it during populate_lazy.
  ModuleSet modules;
  modules.emplace("vmlinux");
  for (std::string line; std::getline(modules_file, line);) {
    // /proc/modules format: name size refcount deps state addr
    // We only need the name (first space-separated field)
    auto space_pos = line.find(' ');
    if (space_pos != std::string::npos) {
      modules.insert(line.substr(0, space_pos));
    }
  }

  return modules;
}

static Result<ModulesFuncsMap> parse_tracepoints()
{
  std::ifstream tracepoints_file(tracefs::available_events());
  if (tracepoints_file.fail()) {
    return make_error<SystemError>("Error reading events from " +
                                   tracefs::available_events());
  }

  ModulesFuncsMap result;
  for (std::string line; std::getline(tracepoints_file, line);) {
    // Events format is simple `category:name`.
    line = util::trim(line);
    auto colon_pos = line.find(':');
    if (colon_pos != std::string::npos) {
      auto category = line.substr(0, colon_pos);
      auto event = line.substr(colon_pos + 1);
      auto it = result.find(category);
      if (it == result.end()) {
        it = result.emplace(category, std::make_shared<FunctionSet>()).first;
      }
      it->second->emplace(event);
    }
  }

  return result;
}

static Result<std::map<std::string, btf::Types>> parse_btf()
{
  std::map<std::string, btf::Types> result;

  // Load the vmlnux BTF.
  auto *vmlinux_btf = btf__load_vmlinux_btf();
  if (!vmlinux_btf) {
    return make_error<SystemError>("failed to load vmlinux BTF");
  }
  btf::Types vmlinux(vmlinux_btf);
  result.emplace("vmlinux", vmlinux);

  // Load all available BTFs from the host kernel.
  char name[64];
  struct bpf_btf_info info = {};
  info.name = reinterpret_cast<uintptr_t>(&name[0]);
  info.name_len = sizeof(name);
  __u32 id = 0, info_len = sizeof(info);

  while (true) {
    int err = bpf_btf_get_next_id(id, &id);
    if (err != 0 && errno == ENOENT) {
      break;
    } else if (err != 0) {
      return make_error<SystemError>("bpf_btf_get_next_id failed");
    }
    int fd = bpf_btf_get_fd_by_id(id);
    if (fd < 0) {
      return make_error<SystemError>("bpf_btf_get_fd_by_id failed");
    }
    if (bpf_obj_get_info_by_fd(fd, &info, &info_len) != 0) {
      return make_error<SystemError>("bpf_obj_get_info_by_fd failed");
    }
    if (info.kernel_btf) {
      auto *mod_btf = btf__load_from_kernel_by_id_split(id, vmlinux_btf);
      if (!mod_btf) {
        return make_error<SystemError>("failed to load module BTF");
      }
      result.emplace(std::string(reinterpret_cast<const char *>(&name[0])),
                     btf::Types(mod_btf, vmlinux));
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
  auto has_ksrc = util::is_dir(ksrc);
  auto has_kobj = util::is_dir(kobj);
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

  auto kconfig_path = ksrc + "/include/linux/kconfig.h";
  if (access(kconfig_path.c_str(), R_OK) == 0) {
    cflags.emplace_back("-include");
    cflags.push_back(kconfig_path);
  }

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

void KernelInfoImpl::add_function(const std::string &func_name,
                                  const std::string &mod_name) const
{
  // Check to see if this is blocked.
  auto blocklist_it = blocklist_.find(mod_name);
  if (is_bad_func(func_name) || (blocklist_it != blocklist_.end() &&
                                 blocklist_it->second->contains(func_name))) {
    return;
  }

  // Check to see if this is a stub for a raw tracepoint.
  for (const auto &prefix : RT_BTF_PREFIXES) {
    if (func_name.starts_with(prefix)) {
      auto final_func_name = func_name;
      final_func_name.erase(0, prefix.length());

      auto raw_tracepoint_it = raw_tracepoints_.find(mod_name);
      if (raw_tracepoint_it == raw_tracepoints_.end()) {
        raw_tracepoint_it = raw_tracepoints_
                                .emplace(mod_name,
                                         std::make_shared<FunctionSet>())
                                .first;
      }
      raw_tracepoint_it->second->insert(final_func_name);
    }
  }

  // Add as a regular traceable function.
  auto module_it = modules_.find(mod_name);
  if (module_it == modules_.end()) {
    module_it =
        modules_.emplace(mod_name, std::make_shared<FunctionSet>()).first;
  }
  module_it->second->insert(func_name);
}

void KernelInfoImpl::populate_lazy(
    const std::optional<std::string> &mod_name) const
{
  if (!available_filter_functions_ || available_filter_functions_->eof()) {
    return;
  }

  // Add everything that is loaded but missing from our set.
  ModuleSet filtered = get_modules(mod_name);
  ModuleSet missing;
  for (const auto &mod : filtered) {
    if (!modules_populated_.contains(mod)) {
      missing.emplace(mod);
    }
  }

  while (!missing.empty() && !available_filter_functions_->eof()) {
    std::string module;
    if (last_checked_line_.empty()) {
      module = "vmlinux";
    } else {
      // N.B. we didn't insert on the last iteration, so this needs
      // be inserted now as the first symbol for this module.
      auto func_mod = util::split_symbol_module(last_checked_line_);
      module = func_mod.second;
      add_function(func_mod.first, module);
    }

    std::string line;
    while (std::getline(*available_filter_functions_, line)) {
      auto func_mod = util::split_symbol_module(line);

      // Continue reading until we get all the module functions.
      // Stop when encounter line with the next module.
      if (func_mod.second != module) {
        missing.erase(module);
        modules_populated_.insert(module);
        last_checked_line_ = line;
        break;
      }

      // Add the current function, which will parse whether this is
      // a tracepoint and check the blocklist in the expected way.
      add_function(func_mod.first, module);
    }
  }
}

ModulesFuncsMap KernelInfo::filter(const ModulesFuncsMap &source,
                                   const std::optional<std::string> &mod_name)
{
  if (!mod_name.has_value()) {
    return source; // Not a deep copy, the pointers.
  }

  // Check if it's a single trivial copy.
  if (!util::has_wildcard(*mod_name)) {
    ModulesFuncsMap result;
    auto it = source.find(*mod_name);
    if (it != source.end()) {
      result.emplace(*mod_name, it->second);
    }
    return result;
  }

  // Copy all the filtered modules.
  ModulesFuncsMap result;
  bool start_wildcard, end_wildcard;
  auto wildcard_tokens = util::get_wildcard_tokens(*mod_name,
                                                   start_wildcard,
                                                   end_wildcard);
  for (const auto &mod : source) {
    if (util::wildcard_match(
            mod.first, wildcard_tokens, start_wildcard, end_wildcard)) {
      result.emplace(mod.first, mod.second);
    }
  }
  return result;
}

ModuleSet KernelInfoImpl::get_modules(
    const std::optional<std::string> &mod_name) const
{
  if (!mod_name.has_value()) {
    // Add everything that is loaded.
    return modules_loaded_;
  } else if (!util::has_wildcard(*mod_name)) {
    // Just return the single module.
    ModuleSet single;
    single.emplace(*mod_name);
    return single;
  } else {
    // Match all loaded modules that are not yet in the populated list.
    ModuleSet filtered;
    bool start_wildcard, end_wildcard;
    auto wildcard_tokens = util::get_wildcard_tokens(*mod_name,
                                                     start_wildcard,
                                                     end_wildcard);
    for (const auto &mod : modules_loaded_) {
      if (util::wildcard_match(
              mod, wildcard_tokens, start_wildcard, end_wildcard)) {
        filtered.emplace(mod);
      }
    }
    return filtered;
  }
}

ModulesFuncsMap KernelInfoImpl::get_traceable_funcs(
    const std::optional<std::string> &mod_name) const
{
  populate_lazy(mod_name);
  return filter(modules_, mod_name);
}

ModulesFuncsMap KernelInfoImpl::get_raw_tracepoints(
    const std::optional<std::string> &mod_name) const
{
  populate_lazy(mod_name);
  return filter(raw_tracepoints_, mod_name);
}

ModulesFuncsMap KernelInfoImpl::get_tracepoints(
    const std::optional<std::string> &category_name) const
{
  return filter(tracepoints_, category_name);
}

Result<btf::Types> KernelInfoImpl::load_btf(const std::string &mod_name) const
{
  // We only load once, because they will all be split BTFs.
  if (btf_.empty()) {
    auto result = parse_btf();
    if (!result) {
      return result.takeError();
    }
    btf_ = std::move(*result);
  }

  // Check to see if this BTF exists.
  auto it = btf_.find(mod_name);
  if (it == btf_.end()) {
    return make_error<SystemError>("no BTF available", ENOENT);
  }

  return it->second;
}

Result<KernelInfoImpl> KernelInfoImpl::open(
    const std::string &traceable_functions_file)
{
  KernelInfoImpl info;

  // Load the list of available modules.
  auto modules = parse_modules();
  if (!modules) {
    return modules.takeError();
  }
  info.modules_loaded_ = std::move(*modules);

  // Load the list of available tracepoints.
  auto tracepoints = parse_tracepoints();
  if (!tracepoints) {
    return tracepoints.takeError();
  }
  info.tracepoints_ = std::move(*tracepoints);

  // Open the filter file. Use the file provided by the user, otherwise fall
  // back to tracefs.
  const std::string path = !traceable_functions_file.empty()
                               ? traceable_functions_file
                               : tracefs::available_filter_functions();
  std::ifstream filter_file(path);
  if (filter_file.fail()) {
    LOG(WARNING) << "Could not read functions from " << path
                 << ". Some features/scripts may not work. If this is "
                    "expected, use --traceable-functions to set this path "
                    "manually.";
  } else {
    info.available_filter_functions_ = std::move(filter_file);
  }

  // Load the blocklist if the file is available, otherwise ignore.
  std::ifstream blocklist_funcs(debugfs::kprobes_blacklist());
  if (!blocklist_funcs.fail()) {
    std::string line;

    while (std::getline(blocklist_funcs, line)) {
      auto addr_func_mod = util::split_addrrange_symbol_module(line);
      const std::string &fn = std::get<1>(addr_func_mod);
      const std::string &mod = std::get<2>(addr_func_mod);

      auto it = info.blocklist_.find(mod);
      if (it == info.blocklist_.end()) {
        it =
            info.blocklist_.emplace(mod, std::make_shared<FunctionSet>()).first;
      }
      it->second->insert(fn);
    }
  }

  return info;
}

// Helper function for get_bpf_progs.
static std::string get_prog_full_name(const struct bpf_prog_info *prog_info,
                                      int prog_fd)
{
  const char *prog_name = prog_info->name;
  const struct btf_type *func_type;
  struct bpf_func_info finfo = {};
  struct bpf_prog_info info = {};
  __u32 info_len = sizeof(info);

  std::string name = std::string(prog_name);

  if (!prog_info->btf_id || prog_info->nr_func_info == 0) {
    return name;
  }

  info.nr_func_info = 1;
  info.func_info_rec_size = prog_info->func_info_rec_size;
  info.func_info_rec_size = std::min<unsigned long>(info.func_info_rec_size,
                                                    sizeof(finfo));
  info.func_info = reinterpret_cast<__u64>(&finfo);

  if (bpf_prog_get_info_by_fd(prog_fd, &info, &info_len)) {
    return name;
  }

  struct btf *prog_btf = btf__load_from_kernel_by_id(info.btf_id);
  if (!prog_btf) {
    return name;
  }

  func_type = btf__type_by_id(prog_btf, finfo.type_id);
  if (!func_type || !btf_is_func(func_type)) {
    btf__free(prog_btf);
    return name;
  }

  prog_name = btf__name_by_offset(prog_btf, func_type->name_off);
  name = std::string(prog_name);
  btf__free(prog_btf);
  return name;
}

std::vector<std::pair<uint32_t, std::string>> KernelInfoImpl::get_bpf_progs()
    const
{
  std::vector<std::pair<uint32_t, std::string>> ids_and_syms;
  __u32 id = 0;
  while (bpf_prog_get_next_id(id, &id) == 0) {
    int raw_fd = bpf_prog_get_fd_by_id(id);

    if (raw_fd < 0) {
      continue;
    }

    auto fd = util::FD(raw_fd);

    struct bpf_prog_info info = {};
    __u32 info_len = sizeof(info);

    if (bpf_obj_get_info_by_fd(fd, &info, &info_len) != 0) {
      continue;
    }

    if (!info.btf_id) {
      // BPF programs that don't have a BTF id won't load.
      continue;
    }

    ids_and_syms.emplace_back(static_cast<uint32_t>(id),
                              get_prog_full_name(&info, fd));

    // Now let's look at the subprograms if they exist.
    if (info.nr_func_info == 0) {
      continue;
    }

    size_t nr_func_info = info.nr_func_info;
    size_t rec_size = info.func_info_rec_size;

    if (rec_size > std::numeric_limits<std::size_t>::max() / nr_func_info) {
      continue; // This shouldn't happen.
    }

    std::vector<char> fi_mem(nr_func_info * rec_size);

    struct btf *btf = btf__load_from_kernel_by_id(info.btf_id);
    if (!btf) {
      continue;
    }

    SCOPE_EXIT
    {
      btf__free(btf);
    };

    info = {};
    info.nr_func_info = nr_func_info;
    info.func_info_rec_size = rec_size;
    info.func_info = reinterpret_cast<__u64>(fi_mem.data());

    if (bpf_prog_get_info_by_fd(fd, &info, &info_len) != 0) {
      continue;
    }

    auto *func_info = reinterpret_cast<struct bpf_func_info *>(fi_mem.data());

    for (__u32 i = 0; i < nr_func_info; i++) {
      const struct btf_type *t = btf__type_by_id(btf, (func_info + i)->type_id);
      if (!t) {
        continue;
      }

      const char *func_name = btf__name_by_offset(btf, t->name_off);
      ids_and_syms.emplace_back(id, std::string(func_name));
    }
  }

  return ids_and_syms;
}

} // namespace bpftrace::symbols
