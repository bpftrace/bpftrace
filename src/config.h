#pragma once

#include <cstdint>
#include <utility>

#include "types.h"
#include "util/result.h"

namespace bpftrace {

enum class ConfigMissingProbes {
  ignore,
  warn,
  error,
};

enum class ConfigUnstable {
  enable,
  warn,
  error,
};

// Taken from here: https://elixir.bootlin.com/linux/v5.16/source/include/linux/license.h
enum CompatibleBPFLicense {
  GPL,
  GPL_V2,
  GPL_AR,
  DUAL_BSD_GPL,
  DUAL_MIT_GPL,
  DUAL_MPL_GPL
};

static const auto UNSTABLE_IMPORT = "unstable_import";
static const auto UNSTABLE_IMPORT_STATEMENT = "unstable_import_statement";
static const auto UNSTABLE_TSERIES = "unstable_tseries";
static const auto UNSTABLE_ADDR = "unstable_addr";
static const auto UNSTABLE_TYPEINFO = "unstable_typeinfo";

static std::unordered_set<std::string> DEPRECATED_CONFIGS = {
  "symbol_source",
  "max_type_res_iterations",
  "unstable_macro",
  "unstable_map_decl"
};

class Config {
public:
  Config(bool has_cmd = false);

  // Fields can be accessed directly via the callers, although care should be
  // taken not to mutate these fields unless the caller truly intends to change
  // them. The `set` method is provided for external users to set the values.
  Result<OK> set(const std::string &key, uint64_t val);
  Result<OK> set(const std::string &key, const std::string &val);

  // Helpers for analysis of variables.
  bool is_unstable(const std::string &key);
  Result<OK> load_environment();

  static std::string get_license_str(CompatibleBPFLicense license);

  // All configuration options.
  bool cpp_demangle = true;
  bool lazy_symbolication = true;
  bool print_maps_on_exit = true;
  ConfigUnstable unstable_import = ConfigUnstable::warn;
  ConfigUnstable unstable_import_statement = ConfigUnstable::error;
  ConfigUnstable unstable_tseries = ConfigUnstable::warn;
  ConfigUnstable unstable_addr = ConfigUnstable::warn;
  ConfigUnstable unstable_typeinfo = ConfigUnstable::error;
#ifdef HAVE_BLAZESYM
  bool use_blazesym = true;
  bool show_debug_info = true;
#else
  bool use_blazesym = false;
  bool show_debug_info = false;
#endif
  uint64_t log_size = 1000000;
  uint64_t max_bpf_progs = 1024;
  uint64_t max_cat_bytes = 10240;
  uint64_t max_map_keys = 4096;
  uint64_t max_probes = 1024;
  uint64_t max_strlen = 1024;
  uint64_t on_stack_limit = 32;
  uint64_t perf_rb_pages = 0; // See get_buffer_pages
  CompatibleBPFLicense license = CompatibleBPFLicense::GPL;
  std::string str_trunc_trailer = "..";
  ConfigMissingProbes missing_probes = ConfigMissingProbes::error;
  StackMode stack_mode = StackMode::bpftrace;

  // Initialized in the constructor.
  UserSymbolCacheType user_symbol_cache_type;
};

// Specific key has been renamed, must be handled by caller. This may be
// returned by the `Config::set` method if a different key must be used to set
// the value. This is explicitly propagated in order to ensure that the caller
// can appropriately propagate this information to the user.
class RenameError : public ErrorInfo<RenameError> {
public:
  static char ID;
  RenameError(std::string &&name) : name_(std::move(name)) {};
  void log(llvm::raw_ostream &OS) const override;

  // Returns the new key which must be used.
  const std::string &new_name() const
  {
    return name_;
  }

private:
  std::string name_;
};

class LicenseError : public ErrorInfo<LicenseError> {
public:
  static char ID;
  LicenseError(std::string license) : license_(std::move(license)) {};
  void log(llvm::raw_ostream &OS) const override;

  const std::string &license() const
  {
    return license_;
  }

private:
  std::string license_;
};

} // namespace bpftrace
