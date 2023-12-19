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

TEST(ConfigSetter, same_source_cannot_set_twice)
{
  auto config = Config();
  auto config_setter = ConfigSetter(config, ConfigSource::env_var);
  EXPECT_TRUE(config_setter.set(ConfigKeyInt::ast_max_nodes, 10));
  EXPECT_FALSE(config_setter.set(ConfigKeyInt::ast_max_nodes, 11));
}

} // namespace test
} // namespace bpftrace
