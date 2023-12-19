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
  EXPECT_TRUE(config_setter.set(ConfigKeyBool::debug_output, true));
  EXPECT_EQ(config.get(ConfigKeyBool::debug_output), true);

  EXPECT_TRUE(config_setter.set(ConfigKeyBool::no_cpp_demangle, true));
  EXPECT_EQ(config.get(ConfigKeyBool::no_cpp_demangle), true);

  EXPECT_TRUE(config_setter.set(ConfigKeyBool::verify_llvm_ir, true));
  EXPECT_EQ(config.get(ConfigKeyBool::verify_llvm_ir), true);

  EXPECT_TRUE(config_setter.set(ConfigKeyInt::ast_max_nodes, 10));
  EXPECT_EQ(config.get(ConfigKeyInt::ast_max_nodes), 10);

  EXPECT_TRUE(config_setter.set(ConfigKeyInt::cat_bytes_max, 10));
  EXPECT_EQ(config.get(ConfigKeyInt::cat_bytes_max), 10);

  EXPECT_TRUE(config_setter.set(ConfigKeyInt::log_size, 10));
  EXPECT_EQ(config.get(ConfigKeyInt::log_size), 10);

  EXPECT_TRUE(config_setter.set(ConfigKeyInt::map_keys_max, 10));
  EXPECT_EQ(config.get(ConfigKeyInt::map_keys_max), 10);

  EXPECT_TRUE(config_setter.set(ConfigKeyInt::max_probes, 10));
  EXPECT_EQ(config.get(ConfigKeyInt::max_probes), 10);

  EXPECT_TRUE(config_setter.set(ConfigKeyInt::max_bpf_progs, 10));
  EXPECT_EQ(config.get(ConfigKeyInt::max_bpf_progs), 10);

  EXPECT_TRUE(config_setter.set(ConfigKeyInt::max_type_res_iterations, 10));
  EXPECT_EQ(config.get(ConfigKeyInt::max_type_res_iterations), 10);

  EXPECT_TRUE(config_setter.set(ConfigKeyInt::perf_rb_pages, 10));
  EXPECT_EQ(config.get(ConfigKeyInt::perf_rb_pages), 10);

  EXPECT_TRUE(config_setter.set(ConfigKeyInt::strlen, 10));
  EXPECT_EQ(config.get(ConfigKeyInt::strlen), 10);

  EXPECT_TRUE(config_setter.set(ConfigKeyString::str_trunc_trailer, "str"));
  EXPECT_EQ(config.get(ConfigKeyString::str_trunc_trailer), "str");

  EXPECT_TRUE(config_setter.set(StackMode::bpftrace));
  EXPECT_EQ(config.get(ConfigKeyStackMode::default_), StackMode::bpftrace);

  EXPECT_TRUE(config_setter.set(UserSymbolCacheType::per_program));
  EXPECT_EQ(config.get(ConfigKeyUserSymbolCacheType::default_),
            UserSymbolCacheType::per_program);
}

TEST(Config, get_config_key)
{
  auto config = Config();
  EXPECT_TRUE(config.get_config_key("debug_output").has_value());
  EXPECT_TRUE(config.get_config_key("Debug_OutPut").has_value());
  EXPECT_TRUE(config.get_config_key("bpftrace_Debug_OutPut").has_value());
  EXPECT_TRUE(config.get_config_key("BPFTRACE_DEBUG_OUTPUT").has_value());
  EXPECT_FALSE(config.get_config_key("debugoutput").has_value());
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

TEST(ConfigSetter, source_precedence)
{
  auto config = Config();
  auto config_setter_env = ConfigSetter(config, ConfigSource::env_var);
  auto config_setter_script = ConfigSetter(config, ConfigSource::script);

  // env var takes precedence over script
  EXPECT_TRUE(config_setter_env.set(ConfigKeyInt::ast_max_nodes, 10));
  EXPECT_FALSE(config_setter_script.set(ConfigKeyInt::ast_max_nodes, 11));
  EXPECT_EQ(config.get(ConfigKeyInt::ast_max_nodes), 10);

  EXPECT_TRUE(config_setter_script.set(ConfigKeyInt::cat_bytes_max, 19));
  EXPECT_TRUE(config_setter_env.set(ConfigKeyInt::cat_bytes_max, 20));
  EXPECT_EQ(config.get(ConfigKeyInt::cat_bytes_max), 20);
}

TEST(ConfigSetter, same_source_cannot_set_twice)
{
  auto config = Config();
  auto config_setter = ConfigSetter(config, ConfigSource::env_var);
  EXPECT_TRUE(config_setter.set(ConfigKeyInt::ast_max_nodes, 10));
  EXPECT_FALSE(config_setter.set(ConfigKeyInt::ast_max_nodes, 11));
}

TEST(ConfigSetter, valid_source)
{
  auto config = Config();
  auto config_setter_env = ConfigSetter(config, ConfigSource::env_var);
  auto config_setter_script = ConfigSetter(config, ConfigSource::script);

  EXPECT_TRUE(config_setter_env.valid_source(ConfigKeyInt::ast_max_nodes));
  EXPECT_FALSE(config_setter_script.valid_source(ConfigKeyInt::ast_max_nodes));

  EXPECT_TRUE(config_setter_env.valid_source(ConfigKeyInt::map_keys_max));
  EXPECT_TRUE(config_setter_script.valid_source(ConfigKeyInt::map_keys_max));
}

} // namespace test
} // namespace bpftrace
