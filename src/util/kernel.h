#pragma once

#include "util/result.h"

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

using FunctionSet = std::unordered_set<std::string>;
using ModuleSet = std::unordered_set<std::string>;
using ModulesFuncsMap = std::unordered_map<std::string, FunctionSet>;

class TraceableFunctionsReader {
public:
  explicit TraceableFunctionsReader() = default;
  ~TraceableFunctionsReader();

  Result<const FunctionSet &> get_module_funcs(const std::string &mod_name);
  ModuleSet get_func_modules(const std::string &func_name);
  Result<bool> is_traceable_function(const std::string &func_name,
                                     const std::string &mod_name);
  const ModulesFuncsMap &get_all_funcs();

private:
  Result<OK> check_open();
  void blocklist_init();
  std::optional<std::string> populate_next_module();
  Result<std::string> search_module_for_function(const std::string &func_name);

  std::ifstream available_filter_functions_;
  std::string last_checked_line_;

  ModulesFuncsMap modules_;
  ModulesFuncsMap blocklist_;
};

// Interface for checking if kernel functions are traceable.
// This abstraction allows components to check function traceability without
// depending on the BPFtrace god object.
class KernelFunctionInfo {
public:
  virtual ~KernelFunctionInfo() = default;

  // Returns true if the given function is traceable (appears in
  // available_filter_functions).
  virtual bool is_traceable(const std::string &func_name) const = 0;

  // Returns the set of modules (or "vmlinux") where the function appears.
  virtual std::unordered_set<std::string> get_modules(
      const std::string &func_name) const = 0;

  // Returns true iff the given module is loaded.
  virtual bool is_module_loaded(const std::string &module) const = 0;

  // Returns all traceable functions.
  virtual const ModulesFuncsMap &get_traceable_funcs() const = 0;

  // Returns all raw tracepoints.
  virtual const ModulesFuncsMap &get_raw_tracepoints() const = 0;

  // Returns all currently running BPF programs as (id, function_name) pairs.
  virtual std::vector<std::pair<uint32_t, std::string>> get_bpf_progs()
      const = 0;
};

// Concrete implementation of KernelFunctionInfo that loads traceable functions
// from the kernel.
class KernelFunctionInfoImpl : public KernelFunctionInfo {
public:
  KernelFunctionInfoImpl() = default;
  ~KernelFunctionInfoImpl() override = default;

  bool is_traceable(const std::string &func_name) const override;
  std::unordered_set<std::string> get_modules(
      const std::string &func_name) const override;
  bool is_module_loaded(const std::string &module) const override;
  const ModulesFuncsMap &get_traceable_funcs() const override;
  const ModulesFuncsMap &get_raw_tracepoints() const override;
  std::vector<std::pair<uint32_t, std::string>> get_bpf_progs() const override;

  std::unordered_set<std::string> get_raw_tracepoint_modules(
      const std::string &name) const;

private:
  // Lazy loader of traceable functions.
  TraceableFunctionsReader reader_;

  // Lazily loaded cache of traceable functions.
  mutable ModulesFuncsMap traceable_funcs_;
  mutable ModulesFuncsMap raw_tracepoints_;
  mutable std::unordered_set<std::string> modules_;
};

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
