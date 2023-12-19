#pragma once

#include <cstdint>
#include <iostream>
#include <map>
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
};

enum class ConfigKeyBool
{
  debug_output,
  no_cpp_demangle,
  verify_llvm_ir,
};

enum class ConfigKeyInt
{
  ast_max_nodes,
  cat_bytes_max,
  log_size,
  map_keys_max,
  max_probes,
  max_bpf_progs,
  max_type_res_iterations,
  perf_rb_pages,
  strlen,
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

struct ConfigValue
{
  ConfigSource source = ConfigSource::default_;
  std::variant<bool, uint64_t, std::string, StackMode, UserSymbolCacheType>
      value;
};

const std::map<std::string, StackMode> STACK_MODE_MAP = {
  { "bpftrace", StackMode::bpftrace },
  { "perf", StackMode::perf },
  { "raw", StackMode::raw },
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

  Config &config_;

private:
  const ConfigSource source_;
};

} // namespace bpftrace
