#include <climits>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "util/bpf_names.h"
#include "util/cgroup.h"
#include "util/gfp_flags.h"
#include "util/io.h"
#include "util/kernel.h"
#include "util/math.h"
#include "util/paths.h"
#include "util/similar.h"
#include "util/strings.h"
#include "util/symbols.h"
#include "util/system.h"
#include "util/wildcard.h"
#include "gmock/gmock-matchers.h"
#include "gtest/gtest.h"

namespace bpftrace::test::utils {

using namespace bpftrace::util;

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

static void test_erase_parameter_list(std::string input,
                                      std::string_view expected)
{
  erase_parameter_list(input);
  EXPECT_EQ(input, expected);
}

TEST(utils, erase_parameter_list)
{
  // Trivial cases
  test_erase_parameter_list("", "");
  test_erase_parameter_list("()", "");
  test_erase_parameter_list("void foo", "void foo");
  test_erase_parameter_list("void foo()", "void foo");
  test_erase_parameter_list("void foo(Bar &b)", "void foo");
  // Qualified functions
  //   we don't need to handle `noexcept` or trailing return type
  //   because they don't appear in the demangled function name
  test_erase_parameter_list("void foo() &&", "void foo");
  test_erase_parameter_list("void foo() const", "void foo");
  // Templated parameter/function
  test_erase_parameter_list("void foo(Bar<Baz> &b)", "void foo");
  test_erase_parameter_list("void foo(Bar<Baz()> &b)", "void foo");
  test_erase_parameter_list("void foo<Bar()>()", "void foo<Bar()>");
  test_erase_parameter_list("void foo<Bar()>::foo(Bar &b)",
                            "void foo<Bar()>::foo");
  // Function pointer
  test_erase_parameter_list("void foo(void (*func)(int))", "void foo");
  test_erase_parameter_list("void foo(void (*func)(int, Bar<Baz()>))",
                            "void foo");
  // Missing closing parenthesis
  test_erase_parameter_list("void foo(Bar &b", "void foo(Bar &b");
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
  return cwd_path;
}

TEST(utils, resolve_binary_path)
{
  std::string path = "/tmp/bpftrace-test-utils-XXXXXX";
  if (::mkdtemp(path.data()) == nullptr) {
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

  EXPECT_GT(std::filesystem::remove_all(path), 0);
}

TEST(utils, abs_path)
{
  std::string path = "/tmp/bpftrace-test-utils-XXXXXX";
  std::string rel_file = "bpftrace-test-utils-abs-path";
  if (::mkdtemp(path.data()) == nullptr) {
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

  EXPECT_TRUE(std::filesystem::remove(rel_file));
  EXPECT_GT(std::filesystem::remove_all(path), 0);
}

TEST(utils, get_cgroup_hierarchy_roots)
{
  auto roots = get_cgroup_hierarchy_roots();

  // Check that each entry is a proper cgroup filesystem. The first set are
  // cgroupv1 results, and the second set are cgroupv2 results.
  for (auto root : roots[0]) {
    std::filesystem::path root_path(root);
    EXPECT_TRUE(std::filesystem::exists(root_path / "cgroup.procs"));
  }
  for (auto root : roots[1]) {
    std::filesystem::path root_path(root);
    EXPECT_TRUE(std::filesystem::exists(root_path / "cgroup.procs"));
  }
}

TEST(utils, get_cgroup_path_in_hierarchy)
{
  std::string tmpdir = "/tmp/bpftrace-test-utils-XXXXXX";

  if (::mkdtemp(tmpdir.data()) == nullptr) {
    throw std::runtime_error("creating temporary path for tests failed");
  }

  const std::filesystem::path path(tmpdir);
  const std::filesystem::path file_1 = path / "file1";
  const std::filesystem::path subdir = path / "subdir";
  const std::filesystem::path file_2 = subdir / "file2";

  // Make a few files in the directory to imitate cgroup files and get their
  // inodes
  if (!std::filesystem::create_directory(subdir)) {
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

  EXPECT_GT(std::filesystem::remove_all(tmpdir), 0);
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
  char *old_val_ptr = ::getenv(key.c_str());
  std::string old_val = {};

  // we must capture the existing key's value by value, since the invokd
  // function might modify the environment and invalidate old_val_ptr.
  if (old_val_ptr != nullptr) {
    old_val = old_val_ptr;
  }

  auto restore_key = [&key, &old_val]() {
    if (!old_val.empty()) {
      EXPECT_EQ(::setenv(key.c_str(), old_val.c_str(), 1), 0);
    } else {
      EXPECT_EQ(::unsetenv(key.c_str()), 0);
    }
  };

  EXPECT_EQ(::setenv(key.c_str(), val.c_str(), 1), 0);

  try {
    fn();
  } catch (const std::exception &ex) {
    restore_key();
    throw ex;
  }

  restore_key();
}

TEST(utils, with_env_nonexisting_key)
{
  // Test nonexisting variable
  const std::string nonexisting_key = "nonexisting_key";
  const std::string some_value = "some_value";

  with_env(nonexisting_key, some_value, [&]() {
    EXPECT_EQ(::getenv(nonexisting_key.c_str()), some_value);
  });

  EXPECT_EQ(::getenv(nonexisting_key.c_str()), nullptr);
}

TEST(utils, with_env_restoration)
{
  // Test that an existing variable is restored correctly,
  // even with nested environment mutation
  const std::string existing_key = "existing_key";
  const std::string existing_value = "existing_value";
  const std::string random_new_key = "random_new_key";
  const std::string random_new_value = "random_new_value";
  const std::string some_value = "some_value";

  ::setenv(existing_key.c_str(), existing_value.c_str(), 1);

  with_env(existing_key, some_value, [&]() {
    EXPECT_EQ(::getenv(existing_key.c_str()), some_value);
    ::unsetenv(existing_key.c_str());
    ::setenv(random_new_key.c_str(), random_new_value.c_str(), 1);
  });

  EXPECT_EQ(::getenv(existing_key.c_str()), existing_value);

  // Cleanup
  ::unsetenv(existing_key.c_str());
  ::unsetenv(random_new_key.c_str());
}

TEST(utils, find_in_path)
{
  std::string tmpdir = "/tmp/bpftrace-test-utils-XXXXXX";
  ASSERT_TRUE(::mkdtemp(tmpdir.data()));

  // Create some directories
  const std::filesystem::path path(tmpdir);
  const std::filesystem::path usr_bin = path / "usr" / "bin";
  const std::filesystem::path usr_local_bin = path / "usr" / "local" / "bin";
  ASSERT_TRUE(std::filesystem::create_directories(usr_bin));
  ASSERT_TRUE(std::filesystem::create_directories(usr_local_bin));

  // Create some dummy binaries
  const std::filesystem::path usr_bin_echo = usr_bin / "echo";
  const std::filesystem::path usr_local_bin_echo = usr_local_bin / "echo";
  const std::filesystem::path usr_bin_cat = usr_bin / "cat";
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
  EXPECT_TRUE(std::filesystem::remove_all(path));
}

// These tests are a bit hacky and rely on repository structure.
//
// They rely on the fact that the test binary is in the same directory
// as some of the other test binaries.
//
// Hopefully they are easy to maintain. If not, please delete.
TEST(utils, find_near_self)
{
  auto runtime_tests = find_near_self("near_self_file");
  // clang-tidy is not aware ASSERT_*() terminates testcase
  // NOLINTBEGIN(bugprone-unchecked-optional-access)
  ASSERT_TRUE(runtime_tests.has_value());
  EXPECT_TRUE(runtime_tests->filename() == "near_self_file");
  EXPECT_TRUE(std::filesystem::exists(*runtime_tests));
  // NOLINTEND(bugprone-unchecked-optional-access)

  EXPECT_FALSE(find_near_self("SHOULD_NOT_EXIST").has_value());
}

TEST(utils, get_pids_for_program)
{
  auto pids = get_pids_for_program("/proc/self/exe");
  ASSERT_TRUE(bool(pids));
  EXPECT_THAT(*pids, testing::Contains(getpid()));

  pids = get_pids_for_program("/doesnotexist");
  ASSERT_FALSE(bool(pids));
}

TEST(utils, round_up_to_next_power_of_two)
{
  // 2^31 = 2147483648 which is max power of 2 within uint32_t
  constexpr uint32_t max_power_of_two = 2147483648;
  ASSERT_EQ(round_up_to_next_power_of_two(0), 0);
  ASSERT_EQ(round_up_to_next_power_of_two(1), 1);
  ASSERT_EQ(round_up_to_next_power_of_two(7), 8);
  ASSERT_EQ(round_up_to_next_power_of_two(55), 64);
  ASSERT_EQ(round_up_to_next_power_of_two(128), 128);
  ASSERT_EQ(round_up_to_next_power_of_two(max_power_of_two - 1),
            max_power_of_two);
  ASSERT_EQ(round_up_to_next_power_of_two(max_power_of_two), max_power_of_two);
}

TEST(utils, cat_file_success)
{
  std::string test_content = "Hello, cat_file test!\nThis is line 2.\n";
  char filename[] = "/tmp/bpftrace-test-cat-file-XXXXXX";
  int fd = mkstemp(filename);
  ASSERT_NE(fd, -1) << "Failed to create temporary file";
  ASSERT_EQ(write(fd, test_content.c_str(), test_content.length()),
            static_cast<ssize_t>(test_content.length()));
  close(fd);

  // Test cat_file with the temporary file
  std::stringstream out;
  cat_file(filename, 1024, out);

  // Verify output matches the file content
  EXPECT_EQ(test_content, out.str());

  // Cleanup
  unlink(filename);
}

TEST(utils, cat_file_nonexistent)
{
  // Path to a file that shouldn't exist
  std::string nonexistent_file = "/tmp/bpftrace-nonexistent-file-test-XXXXXX";
  int fd = mkstemp(const_cast<char *>(nonexistent_file.c_str()));
  close(fd);
  unlink(nonexistent_file.c_str()); // Ensure file doesn't exist

  testing::internal::CaptureStderr();

  // Test cat_file with nonexistent file
  std::stringstream out;
  cat_file(nonexistent_file.c_str(), 1024, out);

  // Get captured stderr
  std::string stderr_output = testing::internal::GetCapturedStderr();

  // Verify no output was produced
  EXPECT_TRUE(out.str().empty())
      << "cat_file should not output anything for nonexistent files";

  // Verify error message was logged
  EXPECT_THAT(stderr_output, testing::HasSubstr("failed to open file"))
      << "Error message should indicate file opening failure";
}

TEST(utils, similar)
{
  // This is not well-defined, and therefore we cannot include whitebox tests
  // that go into much detail. These tests provide a generic `very different`
  // versus `quite similar` sanity baseline.
  EXPECT_FALSE(is_similar("foo", "bar"));
  EXPECT_FALSE(is_similar("foo", "baz"));
  EXPECT_TRUE(is_similar("foo", "foofoo"));
  EXPECT_TRUE(is_similar("fo", "foo"));
  EXPECT_TRUE(is_similar("foobar", "fobar"));
}

TEST(utils, gfp_flags_format)
{
  // Test zero value
  EXPECT_EQ(GFPFlags::format(0), "0");

  // Test individual flags
  EXPECT_EQ(GFPFlags::format(0x01), "__GFP_DMA");
  EXPECT_EQ(GFPFlags::format(0x02), "__GFP_HIGHMEM");
  EXPECT_EQ(GFPFlags::format(0x04), "__GFP_DMA32");
  EXPECT_EQ(GFPFlags::format(0x40), "__GFP_IO");
  EXPECT_EQ(GFPFlags::format(0x80), "__GFP_FS");

  // Test combined individual flags
  EXPECT_EQ(GFPFlags::format(0x41), "__GFP_DMA|__GFP_IO");
  EXPECT_EQ(GFPFlags::format(0xC0), "__GFP_IO|__GFP_FS");

  // Test compound flags (GFP_KERNEL = __GFP_DIRECT_RECLAIM | __GFP_IO |
  // __GFP_FS | __GFP_KSWAPD_RECLAIM) GFP_KERNEL = 0x40000 | 0x40 | 0x80 |
  // 0x100000 = 0x1400C0
  EXPECT_EQ(GFPFlags::format(0x1400C0), "GFP_KERNEL");

  // Test GFP_ATOMIC (__GFP_HIGH | __GFP_ATOMIC | __GFP_KSWAPD_RECLAIM)
  // GFP_ATOMIC = 0x20 | 0x10000 | 0x100000 = 0x110020
  EXPECT_EQ(GFPFlags::format(0x110020), "GFP_ATOMIC");

  // Test unrecognized bits
  EXPECT_EQ(GFPFlags::format(0x80000000), "0x80000000");

  // Test combination of known and unknown flags
  EXPECT_EQ(GFPFlags::format(0x80000001), "__GFP_DMA|0x80000000");
}

} // namespace bpftrace::test::utils
