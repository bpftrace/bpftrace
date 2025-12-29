#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace bpftrace::util {

enum KernelVersionMethod { vDSO, UTS, File, None };
uint32_t kernel_version(KernelVersionMethod method);

std::optional<std::string> find_vmlinux(struct symbol *sym = nullptr);

using FuncsModulesMap =
    std::unordered_map<std::string, std::unordered_set<std::string>>;

FuncsModulesMap parse_traceable_funcs();
FuncsModulesMap parse_rawtracepoints();

struct KConfig {
  KConfig();
  bool has_value(const std::string &name, const std::string &value) const
  {
    auto c = config.find(name);
    return c != config.end() && c->second == value;
  }

  std::unordered_map<std::string, std::string> config;
};

bool get_kernel_dirs(const struct utsname &utsname,
                     std::string &ksrc,
                     std::string &kobj);

std::vector<std::string> get_kernel_cflags(const char *uname_machine,
                                           const std::string &ksrc,
                                           const std::string &kobj,
                                           const KConfig &kconfig);

} // namespace bpftrace::util
