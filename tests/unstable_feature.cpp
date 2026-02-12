#include "ast/passes/unstable_feature.h"
#include "ast/passes/config_analyser.h"
#include "driver.h"
#include "mocks.h"
#include "gtest/gtest.h"

namespace bpftrace::test::unstable_feature {

using ::testing::HasSubstr;

void test(const std::string& input, const std::string& error = "")
{
  auto mock_bpftrace = get_mock_bpftrace();
  BPFtrace& bpftrace = *mock_bpftrace;

  // The input provided here is embedded into an expression.
  ast::ASTContext ast("stdin", input);
  std::stringstream msg;
  msg << "\nInput:\n" << input << "\n\nOutput:\n";

  auto ok = ast::PassManager()
                .put(ast)
                .put(bpftrace)
                .add(CreateParsePass())
                .add(ast::CreateConfigPass())
                .add(ast::CreateUnstableFeaturePass())
                .run();

  std::ostringstream out;
  ast.diagnostics().emit(out);

  if (error.empty()) {
    ASSERT_TRUE(ok && ast.diagnostics().ok()) << msg.str() << out.str();
  } else {
    ASSERT_FALSE(ok && ast.diagnostics().ok()) << msg.str() << out.str();
    EXPECT_THAT(out.str(), HasSubstr(error)) << msg.str() << out.str();
  }
}

void test_error(const std::string& input, const std::string& error)
{
  test(input, error);
}

TEST(unstable_feature, check_error)
{
  test("config = { unstable_tseries=warn } begin { @ = tseries(4, 1s, 10); }");
  test_error(
      "config = { unstable_tseries=error } begin { @ = tseries(4, 1s, 10); }",
      "tseries feature is not enabled by default. To enable this unstable "
      "feature, set the config flag to enable. unstable_tseries=enable");

  test("config = { unstable_addr=warn } begin { $x = 1; &$x; }");
  test_error("config = { unstable_addr=error } begin { $x = 1; &$x; }",
             "address-of operator (&) feature is not enabled by default. To "
             "enable this unstable "
             "feature, set the config flag to enable. unstable_addr=enable");
  test("config = { unstable_addr=warn } begin { @x = 1; &@x; }");
  test_error("config = { unstable_addr=error } begin { @x = 1; &@x; }",
             "address-of operator (&) feature is not enabled by default. To "
             "enable this unstable "
             "feature, set the config flag to enable. unstable_addr=enable");
}

} // namespace bpftrace::test::unstable_feature
