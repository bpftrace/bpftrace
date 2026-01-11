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

// Interface for checking if kernel functions are traceable.
// This abstraction allows BTF to check function traceability without
// depending on the BPFtrace god object.
class KernelFunctionInfo {
public:
  virtual ~KernelFunctionInfo() = default;

  // Returns true if the given function is traceable (appears in
  // available_filter_functions).
  virtual bool is_traceable(const std::string& func_name) const = 0;

  // Returns the set of modules (or "vmlinux") where the function appears.
  virtual std::unordered_set<std::string> get_modules(
      const std::string& func_name) const = 0;

  // Returns all traceable functions.
  virtual const FuncsModulesMap& get_traceable_funcs() const = 0;

  // Returns all raw tracepoints.
  virtual const FuncsModulesMap& get_raw_tracepoints() const = 0;

  // Returns all currently running BPF programs as (id, function_name) pairs.
  virtual std::vector<std::pair<uint32_t, std::string>> get_bpf_progs() const = 0;
};

// Concrete implementation of KernelFunctionInfo that loads traceable functions
// from the kernel.
class KernelFunctionInfoImpl : public KernelFunctionInfo {
public:
  KernelFunctionInfoImpl() = default;
  ~KernelFunctionInfoImpl() override = default;

  bool is_traceable(const std::string& func_name) const override;
  std::unordered_set<std::string> get_modules(
      const std::string& func_name) const override;
  const FuncsModulesMap& get_traceable_funcs() const override;
  const FuncsModulesMap& get_raw_tracepoints() const override;
  std::vector<std::pair<uint32_t, std::string>> get_bpf_progs() const override;

  std::unordered_set<std::string> get_raw_tracepoint_modules(
      const std::string& name) const;

private:
  // Lazily loaded cache of traceable functions
  mutable FuncsModulesMap traceable_funcs_;
  mutable FuncsModulesMap raw_tracepoints_;
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

bool is_module_loaded(const std::string &module);

} // namespace bpftrace::util
