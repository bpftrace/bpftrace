#include "utils.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

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
  EXPECT_EQ(split_string("--", '-', true), tokens_empty);
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

static void symlink_test_binary(const std::string& destination)
{
  if (symlink("/proc/self/exe", destination.c_str()))
  {
    throw std::runtime_error("Couldn't symlink /proc/self/exe to " +
                             destination + ": " + strerror(errno));
  }
}

static std::string get_working_path()
{
  char cwd_path[PATH_MAX];
  if (::getcwd(cwd_path, PATH_MAX) == nullptr)
  {
    throw std::runtime_error(
        "getting current working directory for tests failed");
  }
  return std::string(cwd_path);
}

TEST(utils, resolve_binary_path)
{
  std::string path = "/tmp/bpftrace-test-utils-XXXXXX";
  if (::mkdtemp(&path[0]) == nullptr) {
    throw std::runtime_error("creating temporary path for tests failed");
  }

  // We need real elf executables, linking test binary allows us to do that
  // without additional dependencies.
  symlink_test_binary(path + "/executable");
  symlink_test_binary(path + "/executable2");

  int fd;
  fd = open((path + "/nonexecutable").c_str(), O_CREAT, S_IRUSR); close(fd);
  fd = open((path + "/nonexecutable2").c_str(), O_CREAT, S_IRUSR); close(fd);

  std::vector<std::string> paths_empty = {};
  std::vector<std::string> paths_one_executable = {path + "/executable"};
  std::vector<std::string> paths_all_executables = {path + "/executable", path + "/executable2"};

  EXPECT_EQ(resolve_binary_path(path + "/does/not/exist"), paths_empty);
  EXPECT_EQ(resolve_binary_path(path + "/does/not/exist*"), paths_empty);
  EXPECT_EQ(resolve_binary_path(path + "/nonexecutable"), paths_empty);
  EXPECT_EQ(resolve_binary_path(path + "/nonexecutable*"), paths_empty);
  EXPECT_EQ(resolve_binary_path(path + "/executable"), paths_one_executable);
  EXPECT_EQ(resolve_binary_path(path + "/executable*"), paths_all_executables);
  EXPECT_EQ(resolve_binary_path(path + "/*executable*"), paths_all_executables);

  exec_system(("rm -rf " + path).c_str());
}

TEST(utils, parse_exponent)
{
  EXPECT_EQ(parse_exponent((const char*)"1e0"), 1e0);
  EXPECT_EQ(parse_exponent((const char*)"1e1"), 1e1);
  EXPECT_EQ(parse_exponent((const char*)"1e9"), 1e9);
  EXPECT_EQ(parse_exponent((const char*)"2e1"), 2e1);
  EXPECT_EQ(parse_exponent((const char*)"2e9"), 2e9);
  EXPECT_EQ(parse_exponent((const char*)"2e9"), 2e9);
  EXPECT_EQ(parse_exponent((const char*)"010e010"), 1e11);

  EXPECT_EQ(parse_exponent((const char*)"2a9"), 2ULL);
}

TEST(utils, abs_path)
{
  std::string path = "/tmp/bpftrace-test-utils-XXXXXX";
  std::string rel_file = "bpftrace-test-utils-abs-path";
  if (::mkdtemp(&path[0]) == nullptr)
  {
    throw std::runtime_error("creating temporary path for tests failed");
  }

  int fd;
  fd = open((path + "/somefile").c_str(), O_CREAT, S_IRUSR);
  close(fd);
  fd = open(rel_file.c_str(), O_CREAT, S_IRUSR);
  close(fd);

  // Translates absolute path with '../..'
  EXPECT_EQ(abs_path(path + "/../.." + path + "/somefile"), path + "/somefile");
  // Translates relative path with './'
  EXPECT_EQ(abs_path("./" + rel_file), get_working_path() + "/" + rel_file);

  // /proc/<pid>/root path returned as is (and doesn't throw)
  EXPECT_NO_THROW(
      abs_path(std::string("/proc/1/root/usr/local/bin/usdt_test.so")));
  EXPECT_EQ(abs_path(std::string("/proc/1/root/usr/local/bin/usdt_test.so")),
            std::string("/proc/1/root/usr/local/bin/usdt_test.so"));

  remove(rel_file.c_str());
}

} // namespace utils
} // namespace test
} // namespace bpftrace
