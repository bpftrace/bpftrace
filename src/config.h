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

  // All configuration options.
  bool cpp_demangle = true;
  bool lazy_symbolication = true;
  bool print_maps_on_exit = true;
  bool unstable_map_decl = false;
  bool unstable_import = false;
#ifdef HAVE_BLAZESYM
  bool use_blazesym = true;
#else
  bool use_blazesym = false;
#endif
  uint64_t log_size = 1000000;
  uint64_t max_bpf_progs = 1024;
  uint64_t max_cat_bytes = 10240;
  uint64_t max_map_keys = 4096;
  uint64_t max_probes = 1024;
  uint64_t max_strlen = 1024;
  uint64_t max_type_res_iterations = 0;
  uint64_t on_stack_limit = 32;
  uint64_t perf_rb_pages = 64;
  std::string license = "GPL";
  std::string str_trunc_trailer = "..";
  ConfigMissingProbes missing_probes = ConfigMissingProbes::warn;
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

} // namespace bpftrace
