#include "ast/passes/config_analyser.h"
#include "ast/passes/parser.h"
#include "ast/passes/semantic_analyser.h"
#include "mocks.h"
#include "gtest/gtest.h"

namespace bpftrace::test::config_analyser {

using ::testing::_;

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
                .add(ast::AllParsePasses())
                .add(ast::CreateSemanticPass())
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
  test("config = { BAD_CONFIG=1 } BEGIN { }", false);
  test("config = { BPFTRACE_MAX_MAP_KEYS=1 } BEGIN { }", true);

  test("config = { BPFTRACE_MAX_MAP_KEYS=perf } BEGIN { }", false);
  test("config = { BPFTRACE_STACK_MODE=perf } BEGIN { }", true);
  test("config = { stack_mode=perf } BEGIN { }", true);
  test("config = { BPFTRACE_MAX_MAP_KEYS=1; stack_mode=perf } BEGIN { $ns = "
       "nsecs(); }",
       true);
  test("config = { BPFTRACE_CACHE_USER_SYMBOLS=\"PER_PROGRAM\" } BEGIN { $ns = "
       "nsecs(); }",
       true);
}

TEST(config_analyser, config_error)
{
  test("config = { BAD_CONFIG=1 } BEGIN { }",
       R"(stdin:1:12-23: ERROR: Unrecognized config variable: BAD_CONFIG
config = { BAD_CONFIG=1 } BEGIN { }
           ~~~~~~~~~~~
)",
       false);
  test(
      "config = { BPFTRACE_MAX_PROBES=\"hello\" } BEGIN { }",
      R"(stdin:1:12-32: ERROR: Invalid type for BPFTRACE_MAX_PROBES. Type: string. Expected Type: int
config = { BPFTRACE_MAX_PROBES="hello" } BEGIN { }
           ~~~~~~~~~~~~~~~~~~~~
)",
      false);
  test(
      "config = { max_ast_nodes=1 } BEGIN { }",
      R"(stdin:1:12-26: ERROR: max_ast_nodes can only be set as an environment variable
config = { max_ast_nodes=1 } BEGIN { }
           ~~~~~~~~~~~~~~
)",
      false);
}

TEST(config_analyser, config_setting)
{
  auto bpftrace = get_mock_bpftrace();

  EXPECT_NE(bpftrace->config_->get(ConfigKeyInt::max_map_keys), 9);
  test(*bpftrace, "config = { BPFTRACE_MAX_MAP_KEYS=9 } BEGIN { }");
  EXPECT_EQ(bpftrace->config_->get(ConfigKeyInt::max_map_keys), 9);

  EXPECT_NE(bpftrace->config_->get(ConfigKeyStackMode::default_),
            StackMode::perf);
  test(*bpftrace, "config = { stack_mode=perf } BEGIN { }");
  EXPECT_EQ(bpftrace->config_->get(ConfigKeyStackMode::default_),
            StackMode::perf);

  EXPECT_NE(bpftrace->config_->get(ConfigKeyUserSymbolCacheType::default_),
            UserSymbolCacheType::per_program);
  EXPECT_NE(bpftrace->config_->get(ConfigKeyInt::log_size), 150);
  test(*bpftrace,
       "config = { BPFTRACE_CACHE_USER_SYMBOLS=\"PER_PROGRAM\"; log_size=150 "
       "} BEGIN { }");
  EXPECT_EQ(bpftrace->config_->get(ConfigKeyUserSymbolCacheType::default_),
            UserSymbolCacheType::per_program);
  EXPECT_EQ(bpftrace->config_->get(ConfigKeyInt::log_size), 150);
  EXPECT_EQ(bpftrace->config_->get(ConfigKeySymbolSource::default_),
            ConfigSymbolSource::symbol_table);
}

} // namespace bpftrace::test::config_analyser
