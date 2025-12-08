#include "ast/passes/config_analyser.h"
#include "driver.h"
#include "mocks.h"
#include "types.h"
#include "gtest/gtest.h"

namespace bpftrace::test::config_analyser {

using ::testing::_;
using ::testing::HasSubstr;

void test(BPFtrace &bpftrace,
          const std::string &input,
          std::string_view expected_error,
          bool expected_result)
{
  ast::ASTContext ast("stdin", input);
  std::stringstream msg;
  msg << "\nInput:\n" << input << "\n\nOutput:\n";

  auto ok = ast::PassManager()
                .put(ast)
                .put(bpftrace)
                .put(get_mock_function_info())
                .add(CreateParsePass())
                .add(ast::CreateConfigPass())
                .run();
  ASSERT_TRUE(bool(ok)) << msg.str();
  EXPECT_EQ(ast.diagnostics().ok(), expected_result) << msg.str();

  if (expected_error.data()) {
    if (!expected_error.empty() && expected_error[0] == '\n')
      expected_error.remove_prefix(1); // Remove initial '\n'

    // Reproduce the full string.
    std::stringstream out;
    ast.diagnostics().emit(out);
    EXPECT_EQ(out.str(), expected_error);
  }
}

ast::ASTContext test_for_warning(BPFtrace &bpftrace,
                                 const std::string &input,
                                 const std::string &warning,
                                 bool invert)
{
  ast::ASTContext ast("stdin", input);

  auto ok = ast::PassManager()
                .put(ast)
                .put(bpftrace)
                .put(get_mock_function_info())
                .add(CreateParsePass())
                .add(ast::CreateConfigPass())
                .run();
  EXPECT_TRUE(bool(ok));

  std::stringstream out;
  ast.diagnostics().emit(out);
  if (invert)
    EXPECT_THAT(out.str(), Not(HasSubstr(warning)));
  else
    EXPECT_THAT(out.str(), HasSubstr(warning));

  return ast;
}

ast::ASTContext test_for_warning(const std::string &input,
                                 const std::string &warning)
{
  auto bpftrace = get_mock_bpftrace();
  return test_for_warning(*bpftrace, input, warning, false);
}

ast::ASTContext test_for_no_warning(const std::string &input,
                                    const std::string &warning)
{
  auto bpftrace = get_mock_bpftrace();
  return test_for_warning(*bpftrace, input, warning, true);
}

void test(const std::string &input, bool expected_result)
{
  auto bpftrace = get_mock_bpftrace();

  test(*bpftrace, input, {}, expected_result);
}

void test(const std::string &input,
          std::string_view expected_error,
          bool expected_result)
{
  auto bpftrace = get_mock_bpftrace();

  test(*bpftrace, input, expected_error, expected_result);
}

void test(BPFtrace &bpftrace, const std::string &input)
{
  test(bpftrace, input, {}, true);
}

TEST(config_analyser, config)
{
  test("config = { BAD_CONFIG=1 } begin { }", false);
  test("config = { BPFTRACE_MAX_MAP_KEYS=1 } begin { }", true);

  test("config = { BPFTRACE_MAX_MAP_KEYS=perf } begin { }", false);
  test("config = { BPFTRACE_STACK_MODE=perf } begin { }", true);
  test("config = { stack_mode=perf } begin { }", true);
  test("config = { BPFTRACE_MAX_MAP_KEYS=1; stack_mode=perf } begin { $ns = "
       "nsecs(); }",
       true);
  test("config = { BPFTRACE_CACHE_USER_SYMBOLS=\"PER_PROGRAM\" } begin { $ns = "
       "nsecs(); }",
       true);
}

TEST(config_analyser, config_error)
{
  test("config = { BAD_CONFIG=1 } begin { }",
       R"(stdin:1:12-24: ERROR: BAD_CONFIG: not a known configuration option
config = { BAD_CONFIG=1 } begin { }
           ~~~~~~~~~~~~
)",
       false);
  test(
      "config = { BPFTRACE_MAX_PROBES = \"hello\" } begin { }",
      R"(stdin:1:12-41: ERROR: BPFTRACE_MAX_PROBES: expecting a number, got hello
config = { BPFTRACE_MAX_PROBES = "hello" } begin { }
           ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
)",
      false);
  test(
      "config = { kernel_build=1 } begin { }",
      R"(stdin:1:12-26: ERROR: kernel_build: can only be set as an environment variable
config = { kernel_build=1 } begin { }
           ~~~~~~~~~~~~~~
)",
      false);
}

TEST(config_analyser, deprecated)
{
  test_for_warning("config = { symbol_source=\"symbol_table\" } begin { }",
                   "symbol_source is deprecated and has no effect");
  test_for_warning("config = { symbol_source=\"zzz\" } begin { }",
                   "symbol_source is deprecated and has no effect");
}

TEST(config_analyser, config_setting)
{
  auto bpftrace = get_mock_bpftrace();

  EXPECT_NE(bpftrace->config_->max_map_keys, 9);
  test(*bpftrace, "config = { BPFTRACE_MAX_MAP_KEYS=9 } begin { }");
  EXPECT_EQ(bpftrace->config_->max_map_keys, 9);

  EXPECT_NE(bpftrace->config_->stack_mode, StackMode::perf);
  test(*bpftrace, "config = { stack_mode=perf } begin { }");
  EXPECT_EQ(bpftrace->config_->stack_mode, StackMode::perf);

  EXPECT_NE(bpftrace->config_->user_symbol_cache_type,
            UserSymbolCacheType::per_program);
  EXPECT_NE(bpftrace->config_->log_size, 150);
  test(*bpftrace,
       "config = { BPFTRACE_CACHE_USER_SYMBOLS=\"PER_PROGRAM\"; log_size=150 "
       "} begin { }");
  EXPECT_EQ(bpftrace->config_->user_symbol_cache_type,
            UserSymbolCacheType::per_program);
  EXPECT_EQ(bpftrace->config_->log_size, 150);
}

} // namespace bpftrace::test::config_analyser
