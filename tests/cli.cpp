#include <cstdlib>
#include <initializer_list>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"

#define main bpftrace_test_main
#include "../src/main.cpp"
#undef main

namespace bpftrace::test {
namespace {

class CliStateGuard {
public:
  CliStateGuard()
      : optind_(optind),
        bt_quiet_(bt_quiet),
        bt_verbose_(bt_verbose),
        dry_run_(dry_run)
  {
  }

  ~CliStateGuard()
  {
    optind = optind_;
    bt_quiet = bt_quiet_;
    bt_verbose = bt_verbose_;
    dry_run = dry_run_;
  }

private:
  int optind_;
  bool bt_quiet_;
  bool bt_verbose_;
  bool dry_run_;
};

Args parse_main_args(std::initializer_list<const char *> args)
{
  CliStateGuard guard;
  std::vector<std::string> storage(args.begin(), args.end());
  std::vector<char *> argv;
  argv.reserve(storage.size() + 1);
  for (auto &arg : storage) {
    argv.push_back(arg.data());
  }
  argv.push_back(nullptr);
  return parse_args(storage.size(), argv.data());
}

TEST(MainCli, parses_doc_mode_without_name_filter)
{
  auto args = parse_main_args({ "bpftrace", "--doc", "a.bt", "b.bt" });

  ASSERT_TRUE(args.doc_name.has_value());
  EXPECT_TRUE(args.doc_name->empty());
  EXPECT_THAT(args.doc_filenames, testing::ElementsAre("a.bt", "b.bt"));
}

TEST(MainCli, parses_doc_mode_with_name_filter_and_output)
{
  auto args = parse_main_args(
      { "bpftrace", "--doc=cgroup", "-o", "docs.md", "src/stdlib/base.bt" });

  ASSERT_TRUE(args.doc_name.has_value());
  EXPECT_EQ(*args.doc_name, "cgroup");
  EXPECT_EQ(args.output_file, "docs.md");
  EXPECT_THAT(args.doc_filenames,
              testing::ElementsAre("src/stdlib/base.bt"));
}

TEST(MainCli, doc_mode_rejects_dash_e)
{
  EXPECT_EXIT(
      {
        parse_main_args(
            { "bpftrace", "--doc", "-e", "BEGIN { 1; }", "stdin.bt" });
        std::exit(0);
      },
      testing::ExitedWithCode(1),
      "--doc conflicts with -e");
}

TEST(MainCli, doc_mode_requires_a_filename)
{
  EXPECT_EXIT(
      {
        parse_main_args({ "bpftrace", "--doc" });
        std::exit(0);
      },
      testing::ExitedWithCode(1),
      "--doc requires at least one filename");
}

} // namespace
} // namespace bpftrace::test
