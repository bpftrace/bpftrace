#pragma once

#include <cstdint>
#include <fstream>
#include <optional>
#include <string>
#include <map>
#include <set>
#include <vector>

#include "util/result.h"
#include "util/symbols.h"
#include "btf/btf.h"

namespace bpftrace::symbols {

enum KernelVersionMethod { vDSO, UTS, File, None };
uint32_t kernel_version(KernelVersionMethod method);

std::optional<std::string> find_vmlinux(struct util::symbol *sym = nullptr);

using FunctionSet = std::set<std::string>;
using ModuleSet = std::set<std::string>;
using ModulesFuncsMap = std::map<std::string, std::shared_ptr<FunctionSet>>;

// Interface for checking if kernel functions are traceable.
//
// This is effectively the top-level abstraction over the system itself.
class KernelInfo {
public:
  virtual ~KernelInfo() = default;

  // Returns the set of available modules.
  virtual ModuleSet get_modules(const std::optional<std::string> &mod_name = std::nullopt) const = 0;

  // Returns all traceable functions.
  virtual ModulesFuncsMap get_traceable_funcs(const std::optional<std::string> &mod_name = std::nullopt) const = 0;

  // Returns all raw tracepoints.
  virtual ModulesFuncsMap get_raw_tracepoints(const std::optional<std::string> &mod_name = std::nullopt) const = 0;

  // Returns all known tracepoints.
  virtual ModulesFuncsMap get_tracepoints(const std::optional<std::string> &category_name = std::nullopt) const = 0;

  // Returns all currently running BPF programs as (id, function_name) pairs.
  virtual std::vector<std::pair<uint32_t, std::string>> get_bpf_progs()
      const = 0;

  // Returns the set of modules (or "vmlinux") where the function appears.
  virtual ModuleSet get_func_modules(
      const std::string &func_name, const std::optional<std::string> &mod_name = std::nullopt) const = 0;

  // Loads the BTF for the given modules.
  virtual Result<btf::Types> load_btf(const std::string &mod_name) const = 0;

  // Returns true if the given function is traceable.
  //
  // This is a simple convenience method.
  virtual bool is_traceable(const std::string &func_name,
                            const std::optional<std::string> &mod_name = std::nullopt) const = 0;

  // Returns true iff the given module is loaded (has anything traceable).
  //
  // This is a simple convenience method.
  virtual bool is_module_loaded(const std::string &mod_name) const = 0;

  // This may be used by derived classes to implement core methods.
  static ModulesFuncsMap filter(
    const ModulesFuncsMap &source,
    const std::optional<std::string> &mod_name);
};

// Implements the all the basic helpers.
//
// Derivations of this class need only provide the core functions.
template <typename T>
class KernelInfoBase : public KernelInfo {
public:
  ModuleSet get_func_modules(
    const std::string &func_name, const std::optional<std::string> &mod_name = std::nullopt) const override
  {
    const auto *impl = static_cast<const T *>(this);
    ModuleSet result;
    for (auto &[found_mod, mod_funcs] : impl->get_traceable_funcs(mod_name)) {
      if (mod_funcs->contains(func_name)) {
        result.emplace(found_mod);
      }
    }
    return result;
  }

  bool is_traceable(const std::string &func_name,
                    const std::optional<std::string> &mod_name = std::nullopt) const override {
                      const auto *impl = static_cast<const T *>(this);
                      auto funcs = impl->get_traceable_funcs(mod_name);
                      return std::ranges::any_of(funcs, [&func_name](const auto &pair) {
                        return pair.second->contains(func_name);
                      });
                    }

  bool is_module_loaded(const std::string &mod_name) const override {
    const auto *impl = static_cast<const T *>(this);
    return !impl->get_modules(mod_name).empty();
  }
};

// Implementation that reads available functions from the kernel.
class KernelInfoImpl : public KernelInfoBase<KernelInfoImpl> {
public:
  static Result<KernelInfoImpl> open();
  KernelInfoImpl(const KernelInfoImpl &other) = delete;
  KernelInfoImpl &operator=(const KernelInfoImpl &other) = delete;
  KernelInfoImpl(KernelInfoImpl &&other) = default;
  KernelInfoImpl &operator=(KernelInfoImpl &&other) = default;
  ~KernelInfoImpl() override = default;

  ModuleSet get_modules(const std::optional<std::string> &mod_name = std::nullopt) const override;
  ModulesFuncsMap get_traceable_funcs(const std::optional<std::string> &mod_name = std::nullopt) const override;
  ModulesFuncsMap get_raw_tracepoints(const std::optional<std::string> &mod_name = std::nullopt) const override;
  ModulesFuncsMap get_tracepoints(const std::optional<std::string> &category_name = std::nullopt) const override;
  Result<btf::Types> load_btf(const std::string &mod_name) const override;

  std::vector<std::pair<uint32_t, std::string>> get_bpf_progs() const override;

private:
  KernelInfoImpl() = default;

  void add_function(const std::string &func_name, const std::string &mod_name) const;
  void populate_lazy(const std::optional<std::string> &mod_name = std::nullopt) const;
  ModulesFuncsMap filter_funcs(const ModulesFuncsMap &source, const std::optional<std::string> &mod_name = std::nullopt) const;

  mutable std::ifstream available_filter_functions_;
  mutable std::string last_checked_line_;

  ModuleSet modules_loaded_;
  ModulesFuncsMap tracepoints_;
  mutable ModuleSet modules_populated_;
  mutable ModulesFuncsMap modules_;
  mutable ModulesFuncsMap raw_tracepoints_;
  mutable std::map<std::string, btf::Types> btf_;
  ModulesFuncsMap blocklist_;
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

} // namespace bpftrace::symbols
