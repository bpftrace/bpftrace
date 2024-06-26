#include <algorithm>
#include <cstring>
#include <fstream>

#include "config.h"
#include "log.h"
#include "types.h"

namespace bpftrace {

Config::Config(bool has_cmd)
{
  config_map_ = {
    { ConfigKeyBool::cpp_demangle, { .value = true } },
    { ConfigKeyBool::lazy_symbolication, { .value = false } },
    { ConfigKeyBool::probe_inline, { .value = false } },
    { ConfigKeyInt::log_size, { .value = (uint64_t)1000000 } },
    { ConfigKeyInt::max_bpf_progs, { .value = (uint64_t)512 } },
    { ConfigKeyInt::max_cat_bytes, { .value = (uint64_t)10240 } },
    { ConfigKeyInt::max_map_keys, { .value = (uint64_t)4096 } },
    { ConfigKeyInt::max_probes, { .value = (uint64_t)512 } },
    { ConfigKeyInt::max_strlen, { .value = (uint64_t)64 } },
    { ConfigKeyInt::max_type_res_iterations, { .value = (uint64_t)0 } },
    { ConfigKeyInt::perf_rb_pages, { .value = (uint64_t)64 } },
    { ConfigKeyStackMode::default_, { .value = StackMode::bpftrace } },
    { ConfigKeyString::str_trunc_trailer, { .value = std::string("..") } },
    { ConfigKeyMissingProbes::default_,
      { .value = ConfigMissingProbes::warn } },
    // by default, cache user symbols per program if ASLR is disabled on system
    // or `-c` option is given
    { ConfigKeyUserSymbolCacheType::default_,
      { .value = (has_cmd || !is_aslr_enabled())
                     ? UserSymbolCacheType::per_program
                     : UserSymbolCacheType::per_pid } },
  };
}

bool Config::can_set(ConfigSource prevSource, ConfigSource source)
{
  if (prevSource == ConfigSource::default_ ||
      (prevSource == ConfigSource::script && source == ConfigSource::env_var)) {
    return true;
  }
  return false;
}

// /proc/sys/kernel/randomize_va_space >= 1
bool Config::is_aslr_enabled()
{
  std::string randomize_va_space_file = "/proc/sys/kernel/randomize_va_space";

  {
    std::ifstream file(randomize_va_space_file);
    if (file.fail()) {
      LOG(V1) << std::strerror(errno) << ": " << randomize_va_space_file;
      // conservatively return true
      return true;
    }

    std::string line;
    if (std::getline(file, line) && std::stoi(line) < 1)
      return false;
  }

  return true;
}

std::map<std::string, StackMode> get_stack_mode_map()
{
  std::map<std::string, StackMode> result;
  for (auto &mode : STACK_MODE_NAME_MAP) {
    result.emplace(mode.second, mode.first);
  }
  return result;
}

std::optional<StackMode> Config::get_stack_mode(const std::string &s)
{
  static auto stack_mode_map = get_stack_mode_map();
  auto found = stack_mode_map.find(s);
  if (found != stack_mode_map.end()) {
    return std::make_optional(found->second);
  }
  return std::nullopt;
}

std::optional<ConfigKey> Config::get_config_key(const std::string &str,
                                                std::string &err)
{
  std::string maybe_key = str;
  static const std::string prefix = "bpftrace_";
  std::transform(maybe_key.begin(),
                 maybe_key.end(),
                 maybe_key.begin(),
                 [](unsigned char c) { return std::tolower(c); });

  if (maybe_key.rfind(prefix, 0) == 0) {
    maybe_key = maybe_key.substr(prefix.length());
  }
  if (ENV_ONLY.find(maybe_key) != ENV_ONLY.end()) {
    err = maybe_key + " can only be set as an environment variable";
    return std::nullopt;
  }

  auto found = CONFIG_KEY_MAP.find(maybe_key);

  if (found == CONFIG_KEY_MAP.end()) {
    err = "Unrecognized config variable: " + str;
    return std::nullopt;
  }

  return std::make_optional<ConfigKey>(found->second);
}

bool ConfigSetter::set_stack_mode(const std::string &s)
{
  auto stack_mode = Config::get_stack_mode(s);
  if (stack_mode.has_value())
    return config_.set(ConfigKeyStackMode::default_,
                       stack_mode.value(),
                       source_);

  LOG(ERROR) << s << " is not a valid StackMode";
  return false;
}

// Note: options 0 and 1 are for compatibility with older versions of bpftrace
bool ConfigSetter::set_user_symbol_cache_type(const std::string &s)
{
  UserSymbolCacheType usct;
  if (s == "PER_PID") {
    usct = UserSymbolCacheType::per_pid;
  } else if (s == "PER_PROGRAM") {
    usct = UserSymbolCacheType::per_program;
  } else if (s == "1") {
    // use the default
    return true;
  } else if (s == "NONE" || s == "0") {
    usct = UserSymbolCacheType::none;
  } else {
    LOG(ERROR) << "Invalid value for cache_user_symbols: valid values are "
                  "PER_PID, PER_PROGRAM, and NONE.";
    return false;
  }
  return config_.set(ConfigKeyUserSymbolCacheType::default_, usct, source_);
}

bool ConfigSetter::set_missing_probes_config(const std::string &s)
{
  ConfigMissingProbes mp;
  if (s == "ignore") {
    mp = ConfigMissingProbes::ignore;
  } else if (s == "warn") {
    mp = ConfigMissingProbes::warn;
  } else if (s == "error") {
    mp = ConfigMissingProbes::error;
  } else {
    LOG(ERROR) << "Invalid value for missing_probes: valid values are "
                  "\"ignore\", \"warn\", and \"error\".";
    return false;
  }
  return config_.set(ConfigKeyMissingProbes::default_, mp, source_);
}

} // namespace bpftrace
