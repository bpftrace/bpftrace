#include "gtest/gtest.h"
#include "utils.h"

namespace bpftrace {
namespace test {
namespace utils {

TEST(utils, split_string)
{
  std::vector<std::string> tokens_empty = {};
  std::vector<std::string> tokens_one_empty = {""};
  std::vector<std::string> tokens_two_empty = {"", ""};
  std::vector<std::string> tokens_f = {"", "f"};
  std::vector<std::string> tokens_foo_bar = {"foo", "bar"};
  std::vector<std::string> tokens_empty_foo_bar = {"", "foo", "bar"};
  std::vector<std::string> tokens_empty_foo_empty_bar = {"", "foo", "", "bar"};
  std::vector<std::string> tokens_empty_foo_bar_biz = {"", "foo", "bar", "biz"};

  EXPECT_EQ(split_string("", '-'), tokens_empty);
  EXPECT_EQ(split_string("-", '-'), tokens_one_empty);
  EXPECT_EQ(split_string("--", '-'), tokens_two_empty);
  EXPECT_EQ(split_string("-f-", '-'), tokens_f);
  EXPECT_EQ(split_string("-foo-bar-", '-'), tokens_empty_foo_bar);
  EXPECT_EQ(split_string("-foo--bar-", '-'), tokens_empty_foo_empty_bar);
  EXPECT_EQ(split_string("-foo-bar-biz-", '-'), tokens_empty_foo_bar_biz);
  EXPECT_EQ(split_string("-foo-bar", '-'), tokens_empty_foo_bar);
  EXPECT_EQ(split_string("foo-bar-", '-'), tokens_foo_bar);
  EXPECT_EQ(split_string("foo-bar", '-'), tokens_foo_bar);
}

TEST(utils, wildcard_match)
{
  std::vector<std::string> tokens_not = {"not"};
  std::vector<std::string> tokens_bar = {"bar"};
  std::vector<std::string> tokens_bar_not = {"bar", "not"};
  std::vector<std::string> tokens_foo = {"foo"};
  std::vector<std::string> tokens_biz = {"biz"};
  std::vector<std::string> tokens_foo_biz = {"foo", "biz"};


  // start: true, end: true
  EXPECT_EQ(wildcard_match("foobarbiz", tokens_not, true, true), false);
  EXPECT_EQ(wildcard_match("foobarbiz", tokens_bar, true, true), true);
  EXPECT_EQ(wildcard_match("foobarbiz", tokens_bar_not, true, true), false);
  EXPECT_EQ(wildcard_match("foobarbiz", tokens_foo, true, true), true);
  EXPECT_EQ(wildcard_match("foobarbiz", tokens_biz, true, true), true);
  EXPECT_EQ(wildcard_match("foobarbiz", tokens_foo_biz, true, true), true);

  // start: false, end: true
  EXPECT_EQ(wildcard_match("foobarbiz", tokens_not, false, true), false);
  EXPECT_EQ(wildcard_match("foobarbiz", tokens_bar, false, true), false);
  EXPECT_EQ(wildcard_match("foobarbiz", tokens_bar_not, false, true), false);
  EXPECT_EQ(wildcard_match("foobarbiz", tokens_foo, false, true), true);
  EXPECT_EQ(wildcard_match("foobarbiz", tokens_biz, false, true), false);
  EXPECT_EQ(wildcard_match("foobarbiz", tokens_foo_biz, false, true), true);

  // start: true, end: false
  EXPECT_EQ(wildcard_match("foobarbiz", tokens_not, true, false), false);
  EXPECT_EQ(wildcard_match("foobarbiz", tokens_bar, true, false), false);
  EXPECT_EQ(wildcard_match("foobarbiz", tokens_bar_not, true, false), false);
  EXPECT_EQ(wildcard_match("foobarbiz", tokens_foo, true, false), false);
  EXPECT_EQ(wildcard_match("foobarbiz", tokens_biz, true, false), true);
  EXPECT_EQ(wildcard_match("foobarbiz", tokens_foo_biz, true, false), true);

  // start: false, end: false
  EXPECT_EQ(wildcard_match("foobarbiz", tokens_not, false, false), false);
  EXPECT_EQ(wildcard_match("foobarbiz", tokens_bar, false, false), false);
  EXPECT_EQ(wildcard_match("foobarbiz", tokens_bar_not, false, false), false);
  EXPECT_EQ(wildcard_match("foobarbiz", tokens_foo, false, false), false);
  EXPECT_EQ(wildcard_match("foobarbiz", tokens_biz, false, false), false);
  EXPECT_EQ(wildcard_match("foobarbiz", tokens_foo_biz, false, false), true);
}

} // namespace ast
} // namespace test
} // namespace bpftrace

