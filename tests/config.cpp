#include "config.h"
#include "mocks.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include <iostream>

namespace bpftrace {
namespace test {

TEST(Config, get_and_set)
{
  auto config = Config();
  auto config_setter = ConfigSetter(config, ConfigSource::env_var);

  // check all the keys
  EXPECT_TRUE(config_setter.set(ConfigKeyBool::cpp_demangle, true));
  EXPECT_EQ(config.get(ConfigKeyBool::cpp_demangle), true);

  EXPECT_TRUE(config_setter.set(ConfigKeyBool::lazy_symbolication, true));
  EXPECT_EQ(config.get(ConfigKeyBool::lazy_symbolication), true);

  EXPECT_TRUE(config_setter.set(ConfigKeyInt::log_size, 10));
  EXPECT_EQ(config.get(ConfigKeyInt::log_size), 10);

  EXPECT_TRUE(config_setter.set(ConfigKeyInt::max_cat_bytes, 10));
  EXPECT_EQ(config.get(ConfigKeyInt::max_cat_bytes), 10);

  EXPECT_TRUE(config_setter.set(ConfigKeyInt::max_map_keys, 10));
  EXPECT_EQ(config.get(ConfigKeyInt::max_map_keys), 10);

  EXPECT_TRUE(config_setter.set(ConfigKeyInt::max_probes, 10));
  EXPECT_EQ(config.get(ConfigKeyInt::max_probes), 10);

  EXPECT_TRUE(config_setter.set(ConfigKeyInt::max_bpf_progs, 10));
  EXPECT_EQ(config.get(ConfigKeyInt::max_bpf_progs), 10);

  EXPECT_TRUE(config_setter.set(ConfigKeyInt::max_strlen, 10));
  EXPECT_EQ(config.get(ConfigKeyInt::max_strlen), 10);

  EXPECT_TRUE(config_setter.set(ConfigKeyInt::max_type_res_iterations, 10));
  EXPECT_EQ(config.get(ConfigKeyInt::max_type_res_iterations), 10);

  EXPECT_TRUE(config_setter.set(ConfigKeyInt::perf_rb_pages, 10));
  EXPECT_EQ(config.get(ConfigKeyInt::perf_rb_pages), 10);

  EXPECT_TRUE(config_setter.set(ConfigKeyString::str_trunc_trailer, "str"));
  EXPECT_EQ(config.get(ConfigKeyString::str_trunc_trailer), "str");

  EXPECT_TRUE(config_setter.set(StackMode::bpftrace));
  EXPECT_EQ(config.get(ConfigKeyStackMode::default_), StackMode::bpftrace);

  EXPECT_TRUE(config_setter.set(UserSymbolCacheType::per_program));
  EXPECT_EQ(config.get(ConfigKeyUserSymbolCacheType::default_),
            UserSymbolCacheType::per_program);

  EXPECT_TRUE(config_setter.set(ConfigMissingProbes::ignore));
  EXPECT_EQ(config.get(ConfigKeyMissingProbes::default_),
            ConfigMissingProbes::ignore);
}

TEST(Config, get_config_key)
{
  auto config = Config();
  std::string err_msg;
  EXPECT_TRUE(config.get_config_key("log_size", err_msg).has_value());
  EXPECT_TRUE(config.get_config_key("Log_Size", err_msg).has_value());
  EXPECT_TRUE(config.get_config_key("bpftrace_log_sIze", err_msg).has_value());
  EXPECT_TRUE(config.get_config_key("BPFTRACE_LOG_SIZE", err_msg).has_value());

  // check the error message
  EXPECT_FALSE(config.get_config_key("logsize", err_msg).has_value());
  EXPECT_EQ(err_msg, "Unrecognized config variable: logsize");

  EXPECT_FALSE(config.get_config_key("max_ast_nodes", err_msg).has_value());
  EXPECT_EQ(err_msg,
            "max_ast_nodes can only be set as an environment variable");
}

TEST(ConfigSetter, set_stack_mode)
{
  auto config = Config();
  auto config_setter = ConfigSetter(config, ConfigSource::env_var);

  EXPECT_FALSE(config_setter.set_stack_mode("invalid"));
  EXPECT_TRUE(config_setter.set_stack_mode("raw"));
  EXPECT_EQ(config.get(ConfigKeyStackMode::default_), StackMode::raw);
}

TEST(ConfigSetter, set_user_symbol_cache_type)
{
  auto config = Config();
  auto config_setter = ConfigSetter(config, ConfigSource::env_var);

  EXPECT_FALSE(config_setter.set_user_symbol_cache_type("invalid"));
  EXPECT_TRUE(config_setter.set_user_symbol_cache_type("NONE"));
  EXPECT_EQ(config.get(ConfigKeyUserSymbolCacheType::default_),
            UserSymbolCacheType::none);
}

TEST(ConfigSetter, set_missing_probes)
{
  auto config = Config();
  auto config_setter = ConfigSetter(config, ConfigSource::script);

  EXPECT_EQ(config.get(ConfigKeyMissingProbes::default_),
            ConfigMissingProbes::warn);
  EXPECT_FALSE(config_setter.set_missing_probes_config("invalid"));
  EXPECT_TRUE(config_setter.set_missing_probes_config("error"));
  EXPECT_EQ(config.get(ConfigKeyMissingProbes::default_),
            ConfigMissingProbes::error);
}

TEST(ConfigSetter, source_precedence)
{
  auto config = Config();
  auto config_setter_env = ConfigSetter(config, ConfigSource::env_var);
  auto config_setter_script = ConfigSetter(config, ConfigSource::script);

  // env var takes precedence over script
  EXPECT_TRUE(config_setter_env.set(ConfigKeyInt::max_map_keys, 10));
  EXPECT_FALSE(config_setter_script.set(ConfigKeyInt::max_map_keys, 11));
  EXPECT_EQ(config.get(ConfigKeyInt::max_map_keys), 10);

  EXPECT_TRUE(config_setter_script.set(ConfigKeyInt::max_cat_bytes, 19));
  EXPECT_TRUE(config_setter_env.set(ConfigKeyInt::max_cat_bytes, 20));
  EXPECT_EQ(config.get(ConfigKeyInt::max_cat_bytes), 20);
}

TEST(ConfigSetter, same_source_cannot_set_twice)
{
  auto config = Config();
  auto config_setter = ConfigSetter(config, ConfigSource::env_var);
  EXPECT_TRUE(config_setter.set(ConfigKeyInt::max_map_keys, 10));
  EXPECT_FALSE(config_setter.set(ConfigKeyInt::max_map_keys, 11));
}

} // namespace test
} // namespace bpftrace
