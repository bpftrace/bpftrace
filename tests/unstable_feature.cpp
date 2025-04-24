#include "ast/passes/unstable_feature.h"
#include "ast/passes/config_analyser.h"
#include "ast/passes/parser.h"
#include "ast/passes/printer.h"
#include "mocks.h"
#include "gtest/gtest.h"

namespace bpftrace::test::unstable_feature {

using ::testing::HasSubstr;

void test(const std::string& input,
          const std::string& error = "",
          const std::string& warn = "",
          bool invert = false)
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
    if (!warn.empty()) {
      if (invert) {
        EXPECT_THAT(out.str(), Not(HasSubstr(warn))) << msg.str() << out.str();
      } else {
        EXPECT_THAT(out.str(), HasSubstr(warn)) << msg.str() << out.str();
      }
    }
  } else {
    ASSERT_FALSE(ok && ast.diagnostics().ok()) << msg.str() << out.str();
    EXPECT_THAT(out.str(), HasSubstr(error)) << msg.str() << out.str();
  }
}

void test_error(const std::string& input, const std::string& error)
{
  test(input, error);
}

void test_warning(const std::string& input, const std::string& warn)
{
  test(input, "", warn);
}

void test_no_warning(const std::string& input, const std::string& warn)
{
  test(input, "", warn, true);
}

TEST(unstable_feature, check_warnings)
{
  test_warning("let @a = lruhash(5); BEGIN { @a[0] = 0; }",
               "Script is using an unstable feature. To prevent this "
               "warning you must explicitly enable the unstable "
               "feature in the config e.g. unstable_map_decl=enable");

  test_warning("macro add_one($x) { $x } BEGIN { @a[0] = 0; }",
               "Script is using an unstable feature. To prevent this "
               "warning you must explicitly enable the unstable "
               "feature in the config e.g. unstable_macro=enable");

  test_warning("config = { unstable_map_decl=warn } macro add_one($x) { $x } "
               "BEGIN { @a[0] = 0; }",
               "Script is using an unstable feature. To prevent this "
               "warning you must explicitly enable the unstable "
               "feature in the config e.g. unstable_macro=enable");

  test_no_warning(
      "config = { unstable_map_decl=enable } let @a = lruhash(5); BEGIN "
      "{ @a[0] = 0; }",
      "Script is using an unstable feature");
  test_no_warning("config = { unstable_map_decl=1 } let @a = lruhash(5); BEGIN "
                  "{ @a[0] = 0; }",
                  "Script is using an unstable feature");
  test_no_warning(
      "config = { unstable_macro=enable } macro add_one($x) { $x } BEGIN "
      "{ @a[0] = 0; }",
      "Script is using an unstable feature");
}

TEST(unstable_feature, check_error)
{
  test_error("config = { unstable_map_decl=0 } let @a = lruhash(5); BEGIN { "
             "@a[0] = 0; }",
             "Feature not enabled by default. To enable this unstable feature, "
             "set the config flag to enable. unstable_map_decl=enable");
  test_error("config = { unstable_macro=0 } macro add_one($x) { $x } BEGIN { "
             "@a[0] = 0; }",
             "Feature not enabled by default. To enable this unstable feature, "
             "set the config flag to enable. unstable_macro=enable");
  test_error(
      "config = { unstable_macro=error } macro add_one($x) { $x } BEGIN { "
      "@a[0] = 0; }",
      "Feature not enabled by default. To enable this unstable feature, "
      "set the config flag to enable. unstable_macro=enable");
}

} // namespace bpftrace::test::unstable_feature
