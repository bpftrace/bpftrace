#include "ast/passes/unstable_feature.h"
#include "ast/passes/config_analyser.h"
#include "ast/passes/parser.h"
#include "ast/passes/printer.h"
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
  ast::Printer printer(out);
  printer.visit(ast.root);
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
  test_error("config = { unstable_map_decl=0 } let @a = lruhash(5); BEGIN { "
             "@a[0] = 0; }",
             "map declarations feature is not enabled by default. To enable "
             "this unstable "
             "feature, "
             "set the config flag to enable. unstable_map_decl=enable");
  test_error("config = { unstable_macro=0 } macro add_one($x) { $x } BEGIN { "
             "@a[0] = 0; add_one(1); }",
             "macros feature is not enabled by default. To enable this "
             "unstable feature, "
             "set the config flag to enable. unstable_macro=enable");
  test_error(
      "config = { unstable_macro=error } macro add_one($x) { $x } BEGIN { "
      "@a[0] = 0; add_one(1); }",
      "macros feature is not enabled by default. To enable this unstable "
      "feature, "
      "set the config flag to enable. unstable_macro=enable");

  test("config = { unstable_macro=warn } macro add_one($x) { $x } BEGIN { "
       "@a[0] = 0; add_one(1); }");
  // Macros have to be called to get the error/warning
  test("config = { unstable_macro=error } macro add_one($x) { $x } BEGIN { "
       "@a[0] = 0; }");

  test("config = { unstable_tseries=warn } BEGIN { @ = tseries(4, 1s, 10); }");
  test_error(
      "config = { unstable_tseries=error } BEGIN { @ = tseries(4, 1s, 10); }",
      "tseries feature is not enabled by default. To enable this unstable "
      "feature, set the config flag to enable. unstable_tseries=enable");
}

} // namespace bpftrace::test::unstable_feature
