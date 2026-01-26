#pragma once

#include <cstdint>
#include <fstream>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace bpftrace::util {

enum KernelVersionMethod { vDSO, UTS, File, None };
uint32_t kernel_version(KernelVersionMethod method);

std::optional<std::string> find_vmlinux(struct symbol *sym = nullptr);

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

using FunctionSet = std::unordered_set<std::string>;
using ModuleSet = std::unordered_set<std::string>;
using ModulesFuncsMap = std::unordered_map<std::string, FunctionSet>;

class TraceableFunctionsReader {
public:
  explicit TraceableFunctionsReader() = default;
  ~TraceableFunctionsReader();

  const FunctionSet &get_module_funcs(const std::string &mod_name);
  ModuleSet get_func_modules(const std::string &func_name);
  bool is_traceable_function(const std::string &func_name,
                            const std::string &mod_name);
  const ModulesFuncsMap &get_all_funcs();

private:
  bool check_open();
  void blocklist_init();
  std::optional<std::string> populate_next_module();
  std::string search_module_for_function(const std::string &func_name);

  std::ifstream available_filter_functions_;
  std::string last_checked_line_;

  ModulesFuncsMap modules_;
  ModulesFuncsMap blocklist_;
  FunctionSet empty_set_;
};
} // namespace bpftrace::util
