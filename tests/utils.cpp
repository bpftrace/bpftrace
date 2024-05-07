#include "utils.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "filesystem.h"

namespace bpftrace {
namespace test {
namespace utils {

TEST(utils, split_string)
{
  std::vector<std::string> tokens_empty = {};
  std::vector<std::string> tokens_one_empty = { "" };
  std::vector<std::string> tokens_two_empty = { "", "" };
  std::vector<std::string> tokens_f = { "", "f" };
  std::vector<std::string> tokens_foo_bar = { "foo", "bar" };
  std::vector<std::string> tokens_empty_foo_bar = { "", "foo", "bar" };
  std::vector<std::string> tokens_empty_foo_empty_bar = {
    "", "foo", "", "bar"
  };
  std::vector<std::string> tokens_empty_foo_bar_biz = {
    "", "foo", "bar", "biz"
  };

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

TEST(utils, split_addrrange_symbol_module)
{
  std::tuple<std::string, std::string, std::string> tokens_ar_sym = {
    "0xffffffff85201511-0xffffffff8520152f", "first_nmi", ""
  };
  std::tuple<std::string, std::string, std::string> tokens_ar_sym_mod = {
    "0xffffffffc17e9373-0xffffffffc17e94ff", "vmx_vmexit", "kvm_intel"
  };

  EXPECT_EQ(split_addrrange_symbol_module(
                "0xffffffff85201511-0xffffffff8520152f	first_nmi"),
            tokens_ar_sym);
  EXPECT_EQ(split_addrrange_symbol_module(
                "0xffffffffc17e9373-0xffffffffc17e94ff	vmx_vmexit "
                "[kvm_intel]"),
            tokens_ar_sym_mod);
}

TEST(utils, wildcard_match)
{
  std::vector<std::string> tokens_not = { "not" };
  std::vector<std::string> tokens_bar = { "bar" };
  std::vector<std::string> tokens_bar_not = { "bar", "not" };
  std::vector<std::string> tokens_foo = { "foo" };
  std::vector<std::string> tokens_biz = { "biz" };
  std::vector<std::string> tokens_foo_biz = { "foo", "biz" };

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

static void symlink_test_binary(const std::string &destination)
{
  if (symlink("/proc/self/exe", destination.c_str())) {
    throw std::runtime_error("Couldn't symlink /proc/self/exe to " +
                             destination + ": " + strerror(errno));
  }
}

static std::string get_working_path()
{
  char cwd_path[PATH_MAX];
  if (::getcwd(cwd_path, PATH_MAX) == nullptr) {
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
  fd = open((path + "/nonexecutable").c_str(), O_CREAT, S_IRUSR);
  close(fd);
  fd = open((path + "/nonexecutable2").c_str(), O_CREAT, S_IRUSR);
  close(fd);

  std::vector<std::string> paths_empty = {};
  std::vector<std::string> paths_one_executable = { path + "/executable" };
  std::vector<std::string> paths_all_executables = { path + "/executable",
                                                     path + "/executable2" };

  EXPECT_EQ(resolve_binary_path(path + "/does/not/exist"), paths_empty);
  EXPECT_EQ(resolve_binary_path(path + "/does/not/exist*"), paths_empty);
  EXPECT_EQ(resolve_binary_path(path + "/nonexecutable"), paths_empty);
  EXPECT_EQ(resolve_binary_path(path + "/nonexecutable*"), paths_empty);
  EXPECT_EQ(resolve_binary_path(path + "/executable"), paths_one_executable);
  EXPECT_EQ(resolve_binary_path(path + "/executable*"), paths_all_executables);
  EXPECT_EQ(resolve_binary_path(path + "/*executable*"), paths_all_executables);

  EXPECT_GT(std_filesystem::remove_all(path), 0);
}

TEST(utils, abs_path)
{
  std::string path = "/tmp/bpftrace-test-utils-XXXXXX";
  std::string rel_file = "bpftrace-test-utils-abs-path";
  if (::mkdtemp(&path[0]) == nullptr) {
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

  EXPECT_TRUE(std_filesystem::remove(rel_file));
  EXPECT_GT(std_filesystem::remove_all(path), 0);
}

TEST(utils, get_cgroup_hierarchy_roots)
{
  auto roots = get_cgroup_hierarchy_roots();

  // Check that each entry is a proper cgroup filesystem
  for (auto root : roots) {
    EXPECT_TRUE(root.first == "cgroup" || root.first == "cgroup2");
    std_filesystem::path root_path(root.second);
    EXPECT_TRUE(std_filesystem::exists(root_path / "cgroup.procs"));
  }
}

TEST(utils, get_cgroup_path_in_hierarchy)
{
  std::string tmpdir = "/tmp/bpftrace-test-utils-XXXXXX";

  if (::mkdtemp(&tmpdir[0]) == nullptr) {
    throw std::runtime_error("creating temporary path for tests failed");
  }

  const std_filesystem::path path(tmpdir);
  const std_filesystem::path file_1 = path / "file1";
  const std_filesystem::path subdir = path / "subdir";
  const std_filesystem::path file_2 = subdir / "file2";

  // Make a few files in the directory to imitate cgroup files and get their
  // inodes
  if (!std_filesystem::create_directory(subdir)) {
    throw std::runtime_error("creating subdirectory for tests failed");
  }
  static_cast<std::ofstream &&>(std::ofstream(file_1) << "File 1 content")
      .close();
  static_cast<std::ofstream &&>(std::ofstream(file_2) << "File 2 content")
      .close();
  struct stat file_1_st, file_2_st;
  if (stat(file_1.c_str(), &file_1_st) < 0 ||
      stat(file_2.c_str(), &file_2_st) < 0) {
    throw std::runtime_error("stat on test files failed");
  }

  // Look for both "cgroup files" by their inode twice (to test caching)
  for (int i = 0; i < 2; i++) {
    EXPECT_EQ(get_cgroup_path_in_hierarchy(file_1_st.st_ino, tmpdir), "/file1");
    EXPECT_EQ(get_cgroup_path_in_hierarchy(file_2_st.st_ino, tmpdir),
              "/subdir/file2");
  }

  EXPECT_GT(std_filesystem::remove_all(tmpdir), 0);
}

TEST(utils, parse_kconfig)
{
  char path[] = "/tmp/configXXXXXX";
  int fd = mkstemp(path);
  const std::string config = "# Intro comment\n"
                             "CONFIG_YES=y\n"
                             "CONFIG_MOD=m\n"
                             "CONFIG_VAL=42\n"
                             "# CONFIG_NO is not set";
  EXPECT_EQ(write(fd, config.c_str(), config.length()), config.length());
  setenv("BPFTRACE_KCONFIG_TEST", path, true);
  close(fd);

  KConfig kconfig;
  ASSERT_TRUE(kconfig.has_value("CONFIG_YES", "y"));
  ASSERT_TRUE(kconfig.has_value("CONFIG_MOD", "m"));
  ASSERT_TRUE(kconfig.has_value("CONFIG_VAL", "42"));
  ASSERT_EQ(kconfig.config.find("CONFIG_NO"), kconfig.config.end());

  unlink(path);
}

TEST(utils, sanitiseBPFProgramName)
{
  const std::string name = "uprobe:/bin/bash:main+0x30";
  const std::string sanitised = sanitise_bpf_program_name(name);
  ASSERT_EQ(sanitised, "uprobe__bin_bash_main_0x30");

  const std::string long_name =
      "uretprobe:/this/is/a/very/long/path/to/a/binary/executable:"
      "this_is_a_very_long_function_name_which_exceeds_the_KSYM_NAME_LEN_"
      "limit_of_BPF_program_name";
  const std::string long_sanitised = sanitise_bpf_program_name(long_name);
  ASSERT_EQ(long_sanitised,
            "uretprobe__this_is_a_very_long_path_to_a_binary_executable_this_"
            "is_a_very_long_function_name_which_exceeds_the_ba30ddc67a52bad2");
}

// Run a function with environment var set to specific value.
// Does its best to clean up env var so it doesn't leak between tests.
static void with_env(const std::string &key,
                     const std::string &val,
                     std::function<void()> fn)
{
  EXPECT_EQ(::setenv(key.c_str(), val.c_str(), 1), 0);
  try {
    fn();
  } catch (const std::exception &ex) {
    EXPECT_EQ(::unsetenv(key.c_str()), 0);
    throw ex;
  }
  EXPECT_EQ(::unsetenv(key.c_str()), 0);
}

TEST(utils, find_in_path)
{
  std::string tmpdir = "/tmp/bpftrace-test-utils-XXXXXX";
  ASSERT_TRUE(::mkdtemp(&tmpdir[0]));

  // Create some directories
  const std_filesystem::path path(tmpdir);
  const std_filesystem::path usr_bin = path / "usr" / "bin";
  const std_filesystem::path usr_local_bin = path / "usr" / "local" / "bin";
  ASSERT_TRUE(std_filesystem::create_directories(usr_bin));
  ASSERT_TRUE(std_filesystem::create_directories(usr_local_bin));

  // Create some dummy binaries
  const std_filesystem::path usr_bin_echo = usr_bin / "echo";
  const std_filesystem::path usr_local_bin_echo = usr_local_bin / "echo";
  const std_filesystem::path usr_bin_cat = usr_bin / "cat";
  {
    std::ofstream(usr_bin_echo) << "zz";
    std::ofstream(usr_local_bin_echo) << "zz";
    std::ofstream(usr_bin_cat) << "zz";
  }

  // Test basic find
  with_env("PATH", usr_bin, [&]() {
    auto f = find_in_path("echo");
    ASSERT_TRUE(f.has_value());
    EXPECT_TRUE(f->native().find("/usr/bin/echo") != std::string::npos);
  });

  // Test no entries found
  with_env("PATH", usr_bin, [&]() {
    auto f = find_in_path("echoz");
    ASSERT_FALSE(f.has_value());
  });

  // Test precedence in find with two entries in $PATH
  auto two_path = usr_local_bin.native() + ":" + usr_bin.native();
  with_env("PATH", two_path, [&]() {
    auto f = find_in_path("echo");
    ASSERT_TRUE(f.has_value());
    EXPECT_TRUE(f->native().find("/usr/local/bin/echo") != std::string::npos);
  });

  // Test no entries found with two entries in $PATH
  with_env("PATH", two_path, [&]() {
    auto f = find_in_path("echoz");
    ASSERT_FALSE(f.has_value());
  });

  // Test empty $PATH
  with_env("PATH", "", [&]() {
    auto f = find_in_path("echo");
    ASSERT_FALSE(f.has_value());
  });

  // Cleanup
  EXPECT_TRUE(std_filesystem::remove_all(path));
}

TEST(utils, get_pids_for_program)
{
  auto pids = get_pids_for_program("/proc/self/exe");

  ASSERT_EQ(pids.size(), 1);
  ASSERT_EQ(pids[0], getpid());

  pids = get_pids_for_program("/proc/12345/root/usr/bin/bash");
  ASSERT_EQ(pids.size(), 0);
}

} // namespace utils
} // namespace test
} // namespace bpftrace
