#pragma once

#include <cstdint>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <variant>

#include "types.h"

namespace bpftrace {

// This is used to determine which source
// takes precedence when a config key is set
enum class ConfigSource
{
  // the default config value
  default_,
  // config set via environment variable
  env_var,
  // config set via config script syntax
  script,
};

enum class ConfigKeyBool
{
  cpp_demangle,
  debug_output,
  verify_llvm_ir,
};

enum class ConfigKeyInt
{
  log_size,
  max_ast_nodes,
  max_bpf_progs,
  max_cat_bytes,
  max_map_keys,
  max_probes,
  max_strlen,
  max_type_res_iterations,
  perf_rb_pages,
};

enum class ConfigKeyString
{
  str_trunc_trailer,
};

enum class ConfigKeyStackMode
{
  default_,
};

enum class ConfigKeyUserSymbolCacheType
{
  default_,
};

typedef std::variant<ConfigKeyBool,
                     ConfigKeyInt,
                     ConfigKeyString,
                     ConfigKeyStackMode,
                     ConfigKeyUserSymbolCacheType>
    ConfigKey;

// These strings match the env variables (minus the 'BPFTRACE_' prefix)
const std::map<std::string, ConfigKey> CONFIG_KEY_MAP = {
  { "cache_user_symbols", ConfigKeyUserSymbolCacheType::default_ },
  { "cpp_demangle", ConfigKeyBool::cpp_demangle },
  { "debug_output", ConfigKeyBool::debug_output },
  { "log_size", ConfigKeyInt::log_size },
  { "max_ast_nodes", ConfigKeyInt::max_ast_nodes },
  { "max_bpf_progs", ConfigKeyInt::max_bpf_progs },
  { "max_cat_bytes", ConfigKeyInt::max_cat_bytes },
  { "max_map_keys", ConfigKeyInt::max_map_keys },
  { "max_probes", ConfigKeyInt::max_probes },
  { "max_strlen", ConfigKeyInt::max_strlen },
  { "max_type_res_iterations", ConfigKeyInt::max_type_res_iterations },
  { "perf_rb_pages", ConfigKeyInt::perf_rb_pages },
  { "stack_mode", ConfigKeyStackMode::default_ },
  { "str_trunc_trailer", ConfigKeyString::str_trunc_trailer },
  { "verify_llvm_ir", ConfigKeyBool::verify_llvm_ir },
};

const std::set<ConfigKey> ENV_ONLY_CONFIGS = {
  ConfigKeyInt::max_ast_nodes,
  ConfigKeyBool::debug_output,
  ConfigKeyBool::verify_llvm_ir,
};

struct ConfigValue
{
  ConfigSource source = ConfigSource::default_;
  std::variant<bool, uint64_t, std::string, StackMode, UserSymbolCacheType>
      value;
};

class Config
{
public:
  explicit Config(bool has_cmd = false, bool bt_verbose = false);

  bool get(ConfigKeyBool key) const
  {
    return get<bool>(key);
  }

  uint64_t get(ConfigKeyInt key) const
  {
    return get<uint64_t>(key);
  }

  std::string get(ConfigKeyString key) const
  {
    return get<std::string>(key);
  }

  StackMode get(ConfigKeyStackMode key) const
  {
    return get<StackMode>(key);
  }

  UserSymbolCacheType get(ConfigKeyUserSymbolCacheType key) const
  {
    return get<UserSymbolCacheType>(key);
  }

  static std::optional<StackMode> get_stack_mode(const std::string &s);
  std::optional<ConfigKey> get_config_key(const std::string &str);

  friend class ConfigSetter;

private:
  template <typename T>
  bool set(ConfigKey key, T val, ConfigSource source)
  {
    auto it = config_map_.find(key);
    if (it == config_map_.end())
    {
      throw std::runtime_error("No default set for config key");
    }
    if (!can_set(it->second.source, source))
    {
      return false;
    }

    it->second.value = val;
    it->second.source = source;
    return true;
  }

  template <typename T>
  T get(ConfigKey key) const
  {
    auto it = config_map_.find(key);
    if (it == config_map_.end())
    {
      throw std::runtime_error("Config key does not exist in map");
    }
    try
    {
      return std::get<T>(it->second.value);
    }
    catch (std::bad_variant_access const &ex)
    {
      // This shouldn't happen
      throw std::runtime_error("Type mismatch for config key");
    }
  }

private:
  bool can_set(ConfigSource prevSource, ConfigSource);
  bool is_aslr_enabled();
  bool bt_verbose_ = false;

  std::map<ConfigKey, ConfigValue> config_map_;
};

class ConfigSetter
{
public:
  explicit ConfigSetter(Config &config, ConfigSource source)
      : config_(config), source_(source){};

  bool set(ConfigKeyBool key, bool val)
  {
    return config_.set(key, val, source_);
  }

  bool set(ConfigKeyInt key, uint64_t val)
  {
    return config_.set(key, val, source_);
  }

  bool set(ConfigKeyString key, const std::string &val)
  {
    return config_.set(key, val, source_);
  }

  bool set(StackMode val)
  {
    return config_.set(ConfigKeyStackMode::default_, val, source_);
  }

  bool set(UserSymbolCacheType val)
  {
    return config_.set(ConfigKeyUserSymbolCacheType::default_, val, source_);
  }

  bool set_stack_mode(const std::string &s);
  bool set_user_symbol_cache_type(const std::string &s);
  bool valid_source(ConfigKey key);

  Config &config_;

private:
  const ConfigSource source_;
};

} // namespace bpftrace
