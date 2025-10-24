#include "ast/location.h"
#include "ast/ast.h"
#include "ast/context.h"
#include "gtest/gtest.h"

namespace bpftrace::test::location {

static std::string test = R"(
i:s:1 {
  print(1, 2);
  print(1, 2, 3, 4);
}
)";

TEST(Location, single_line)
{
  ast::ASTContext ast("testfile", test);

  // Replicate a specific parser error.
  ast::SourceLocation loc(ast.source());
  loc.begin = { .line = 3, .column = 9 };
  loc.end = { .line = 3, .column = 13 };
  auto &call = *ast.make_node<ast::Call>(loc, "foo", ast::ExpressionList({}));
  auto &err = call.addError();

  EXPECT_EQ(err.loc()->source_location(), "testfile:3:9-13");
  EXPECT_EQ(err.loc()->source_context(),
            std::vector<std::string>({
                "  print(1, 2);",
                "        ~~~~",
            }));
}

TEST(Location, multi_line)
{
  ast::ASTContext ast("testfile", test);

  // Replicate a specific parser error, that spans multiple lines.
  ast::SourceLocation loc(ast.source());
  loc.begin = { .line = 3, .column = 3 };
  loc.end = { .line = 4, .column = 19 };
  auto &call = *ast.make_node<ast::Call>(loc, "foo", ast::ExpressionList({}));
  auto &err = call.addError();

  EXPECT_EQ(err.loc()->source_location(), "testfile:3-4");
  EXPECT_EQ(err.loc()->source_context(),
            std::vector<std::string>({
                "  print(1, 2);",
                "  print(1, 2, 3, 4);",
            }));
}

} // namespace bpftrace::test::location
