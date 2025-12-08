#include "ast/passes/deprecated.h"
#include "driver.h"
#include "mocks.h"
#include "gtest/gtest.h"

namespace bpftrace::test::deprecated {

using ::testing::_;
using ::testing::HasSubstr;

void test(BPFtrace &bpftrace,
          const std::string &input,
          const std::string &output)
{
  ast::ASTContext ast("stdin", input);
  auto ok = ast::PassManager()
                .put(ast)
                .put(bpftrace)
                .put(get_mock_function_info())
                .add(CreateParsePass())
                .add(ast::CreateDeprecatedPass())
                .run();
  ASSERT_TRUE(bool(ok));

  std::stringstream out;
  ast.diagnostics().emit(out);
  EXPECT_THAT(out.str(), HasSubstr(output));
}

void test(const std::string &input, const std::string &output)
{
  auto bpftrace = get_mock_bpftrace();
  test(*bpftrace, input, output);
}

TEST(deprecated, sarg)
{
  test("begin { sarg0 }",
       "sarg* is deleted. This was deprecated in v0.21 and was last available "
       "in v0.24.");
}

} // namespace bpftrace::test::deprecated
