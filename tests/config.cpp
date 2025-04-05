#include "config.h"
#include "gmock/gmock-matchers.h"
#include "gtest/gtest.h"

namespace bpftrace::test {

using ::bpftrace::Config;
using ::testing::HasSubstr;

TEST(Config, set)
{
  Config config;

  // Test that this is also true by default, as a requirement.
  EXPECT_TRUE(config.print_maps_on_exit);

  // Check that bool parsing works.
  EXPECT_FALSE(bool(config.set("print_maps_on_exit", "invalid")));
  EXPECT_TRUE(bool(config.set("print_maps_on_exit", "false")));
  EXPECT_FALSE(config.print_maps_on_exit);
  EXPECT_TRUE(bool(config.set("print_maps_on_exit", "true")));
  EXPECT_TRUE(config.print_maps_on_exit);

  // Check that int parsing works.
  EXPECT_TRUE(bool(config.set("log_size", "100")));
  EXPECT_EQ(config.log_size, 100);
  EXPECT_TRUE(bool(config.set("log_size", 101)));
  EXPECT_EQ(config.log_size, 101);
  EXPECT_FALSE(bool(config.set("log_size", "invalid")));
  EXPECT_EQ(config.log_size, 101);

  // Check that string parsing works.
  EXPECT_TRUE(bool(config.set("str_trunc_trailer", "oh, no! we lost bytes!")));
  EXPECT_EQ(config.str_trunc_trailer, "oh, no! we lost bytes!");
  EXPECT_TRUE(bool(config.set("str_trunc_trailer", 0)));
  EXPECT_EQ(config.str_trunc_trailer, "0");

  // Check that enum parsing works.
  EXPECT_FALSE(bool(config.set("stack_mode", "invalid")));
  EXPECT_FALSE(bool(config.set("stack_mode", 0)));
  EXPECT_TRUE(bool(config.set("stack_mode", "bpftrace")));
  EXPECT_EQ(config.stack_mode, StackMode::bpftrace);
  EXPECT_TRUE(bool(config.set("stack_mode", "raw")));
  EXPECT_EQ(config.stack_mode, StackMode::raw);

  EXPECT_FALSE(bool(config.set("cache_user_symbols", "invalid")));
  EXPECT_TRUE(bool(config.set("cache_user_symbols", "NONE")));
  EXPECT_EQ(config.user_symbol_cache_type, UserSymbolCacheType::none);

  EXPECT_EQ(config.missing_probes, ConfigMissingProbes::warn);
  EXPECT_FALSE(bool(config.set("missing_probes", "invalid")));
  EXPECT_TRUE(bool(config.set("missing_probes", "error")));
  EXPECT_EQ(config.missing_probes, ConfigMissingProbes::error);
}

TEST(Config, key_finding)
{
  Config config;

  EXPECT_TRUE(bool(config.set("log_size", 0)));
  EXPECT_TRUE(bool(config.set("Log_Size", 0)));
  EXPECT_TRUE(bool(config.set("bpftrace_log_sIze", 0)));
  EXPECT_TRUE(bool(config.set("BPFTRACE_LOG_SIZE", 0)));
}

static void test_lookup_error(const std::string &key,
                              uint64_t v,
                              const std::string &err)
{
  Config config;
  auto ok = config.set(key, v);
  ASSERT_FALSE(bool(ok));
  std::stringstream ss;
  ss << ok.takeError();
  EXPECT_THAT(ss.str(), HasSubstr(err));
}

TEST(Config, get_config_key)
{
  test_lookup_error("logsize", 1, "logsize: not a known configuration option");
  test_lookup_error(
      "max_ast_nodes",
      1,
      "max_ast_nodes: can only be set as an environment variable");
}

} // namespace bpftrace::test
