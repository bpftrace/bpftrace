#include <cstring>
#include <fstream>

#include "config.h"
#include "log.h"
#include "types.h"

namespace bpftrace {

Config::Config(bool has_cmd, bool bt_verbose) : bt_verbose_(bt_verbose)
{
  config_map_ = {
    // Maximum AST nodes allowed for fuzzing
    { ConfigKeyInt::ast_max_nodes, { .value = (uint64_t)0 } },
    { ConfigKeyInt::cat_bytes_max, { .value = (uint64_t)10240 } },
    { ConfigKeyBool::debug_output, { .value = false } },
    { ConfigKeyInt::log_size, { .value = (uint64_t)1000000 } },
    { ConfigKeyInt::map_keys_max, { .value = (uint64_t)4096 } },
    { ConfigKeyInt::max_probes, { .value = (uint64_t)512 } },
    { ConfigKeyInt::max_bpf_progs, { .value = (uint64_t)512 } },
    { ConfigKeyInt::max_type_res_iterations, { .value = (uint64_t)0 } },
    { ConfigKeyBool::no_cpp_demangle, { .value = false } },
    { ConfigKeyInt::perf_rb_pages, { .value = (uint64_t)64 } },
    { ConfigKeyStackMode::default_, { .value = StackMode::bpftrace } },
    { ConfigKeyInt::strlen, { .value = (uint64_t)64 } },
    { ConfigKeyString::str_trunc_trailer, { .value = ".." } },
    // by default, cache user symbols per program if ASLR is disabled on system
    // or `-c` option is given
    { ConfigKeyUserSymbolCacheType::default_,
      { .value = (has_cmd || !is_aslr_enabled())
                     ? UserSymbolCacheType::per_program
                     : UserSymbolCacheType::per_pid } },
    { ConfigKeyBool::verify_llvm_ir, { .value = false } }
  };
}

bool Config::can_set(ConfigSource prevSource, ConfigSource)
{
  if (prevSource == ConfigSource::default_)
  {
    return true;
  }
  else if (prevSource == ConfigSource::env_var)
  {
    return false;
  }
  return false;
}

// /proc/sys/kernel/randomize_va_space >= 1
bool Config::is_aslr_enabled()
{
  std::string randomize_va_space_file = "/proc/sys/kernel/randomize_va_space";

  {
    std::ifstream file(randomize_va_space_file);
    if (file.fail())
    {
      if (bt_verbose_)
        LOG(ERROR) << std::strerror(errno) << ": " << randomize_va_space_file;
      // conservatively return true
      return true;
    }

    std::string line;
    if (std::getline(file, line) && std::stoi(line) < 1)
      return false;
  }

  return true;
}

bool ConfigSetter::set_stack_mode(const std::string &s)
{
  auto found = STACK_MODE_MAP.find(s);
  if (found != STACK_MODE_MAP.end())
  {
    return config_.set(ConfigKeyStackMode::default_, found->second, source_);
  }
  else
  {
    LOG(ERROR) << s << " is not a valid StackMode";
    return false;
  }
}

// Note: options 0 and 1 are for compatibility with older versions of bpftrace
bool ConfigSetter::set_user_symbol_cache_type(const std::string &s)
{
  UserSymbolCacheType usct;
  if (s == "PER_PID")
  {
    usct = UserSymbolCacheType::per_pid;
  }
  else if (s == "PER_PROGRAM")
  {
    usct = UserSymbolCacheType::per_program;
  }
  else if (s == "1")
  {
    // use the default
    return true;
  }
  else if (s == "NONE" || s == "0")
  {
    usct = UserSymbolCacheType::none;
  }
  else
  {
    LOG(ERROR)
        << "Env var 'BPFTRACE_CACHE_USER_SYMBOLS' did not contain a valid "
           "value: valid values are PER_PID, PER_PROGRAM, and NONE.";
    return false;
  }
  return config_.set(ConfigKeyUserSymbolCacheType::default_, usct, source_);
}

} // namespace bpftrace
