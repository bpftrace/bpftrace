#include "container/cstring_view.h"
#include "gtest/gtest.h"

#include <type_traits>

namespace bpftrace::test::cstring_view {

using bpftrace::cstring_view;

TEST(cstring_view, c_string)
{
  const char *str = "abc";
  cstring_view sv{ str };

  EXPECT_EQ("abc", sv);

  EXPECT_EQ('a', sv[0]);
  EXPECT_EQ('b', sv[1]);
  EXPECT_EQ('c', sv[2]);
  EXPECT_EQ('\0', sv[3]);
}

TEST(cstring_view, std_string)
{
  std::string str = "abc";
  cstring_view sv{ str };

  EXPECT_EQ("abc", sv);

  EXPECT_EQ('a', sv[0]);
  EXPECT_EQ('b', sv[1]);
  EXPECT_EQ('c', sv[2]);
  EXPECT_EQ('\0', sv[3]);
}

TEST(cstring_view, std_string_view)
{
  EXPECT_FALSE((std::is_constructible_v<cstring_view, std::string_view>));

  // Sanity checks:
  EXPECT_TRUE((std::is_constructible_v<cstring_view, std::string>));
  EXPECT_TRUE((std::is_constructible_v<cstring_view, const char *>));
}

TEST(cstring_view, length)
{
  cstring_view sv{ "abc" };

  EXPECT_EQ("abc", sv);
  EXPECT_EQ(3, sv.size());
  EXPECT_EQ(3, sv.length());
}

TEST(cstring_view, c_str)
{
  cstring_view sv{ "abc" };
  EXPECT_EQ(0, strcmp(sv.c_str(), "abc"));
}

} // namespace bpftrace::test::cstring_view
