#include "ast/location.h"
#include "ast/ast.h"
#include "ast/context.h"
#include "gtest/gtest.h"

#include "location.hh"

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
  bpftrace::location loc(position(nullptr, 3, 9), position(nullptr, 3, 13));
  auto &call = *ast.make_node<ast::Call>("foo", ast::ExpressionList({}), loc);
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
  bpftrace::location loc(position(nullptr, 3, 3), position(nullptr, 4, 19));
  auto &call = *ast.make_node<ast::Call>("foo", ast::ExpressionList({}), loc);
  auto &err = call.addError();

  EXPECT_EQ(err.loc()->source_location(), "testfile:3-4");
  EXPECT_EQ(err.loc()->source_context(),
            std::vector<std::string>({
                "  print(1, 2);",
                "  print(1, 2, 3, 4);",
            }));
}

} // namespace bpftrace::test::location
