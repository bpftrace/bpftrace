#include <csignal>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <system_error>

#include "util/proc.h"
#include "llvm/Support/Error.h"
#include "gmock/gmock-matchers.h"
#include "gtest/gtest.h"

namespace bpftrace::test::child {

using bpftrace::util::ChildProc;
using bpftrace::util::create_child;
using ::testing::HasSubstr;

class childproc : public ::testing::Test {
protected:
  void find(std::string &out, const char *path)
  {
    std::error_code ec;
    auto self = std::filesystem::read_symlink("/proc/self/exe", ec);
    ASSERT_FALSE(ec);
    auto parent_dir = self.parent_path();
    out = parent_dir / std::filesystem::path(path);
  }

  void SetUp() override
  {
    find(TEST_BIN, "testprogs/true");
    find(TEST_BIN_ERR, "testprogs/false");
    find(TEST_BIN_SLOW, "testprogs/wait10");
  }

  std::string TEST_BIN;
  std::string TEST_BIN_ERR;
  std::string TEST_BIN_SLOW;
};

TEST_F(childproc, exe_does_not_exist)
{
  auto child = create_child("/does/not/exist/abc/fed");
  EXPECT_FALSE(bool(child));
  EXPECT_THAT(llvm::toString(child.takeError()),
              HasSubstr("does not exist or is not executable"));
}

TEST_F(childproc, child_exit_success)
{
  // Spawn a child that exits successfully
  auto child = create_child(TEST_BIN, true);
  ASSERT_TRUE(bool(child));

  ASSERT_TRUE(bool((*child)->run()));
  ASSERT_TRUE(bool((*child)->wait(1000)));
  EXPECT_FALSE((*child)->is_alive());
  EXPECT_EQ((*child)->exit_code(), 0);
  EXPECT_EQ((*child)->term_signal(), std::nullopt);
}

TEST_F(childproc, child_exit_err)
{
  // Spawn a child that exits with an error
  auto child = create_child(TEST_BIN_ERR, true);
  ASSERT_TRUE(bool(child));

  ASSERT_TRUE(bool((*child)->run()));
  ASSERT_TRUE(bool((*child)->wait(1000)));
  EXPECT_FALSE((*child)->is_alive());
  EXPECT_TRUE((*child)->exit_code().value_or(0) > 0);
  EXPECT_EQ((*child)->term_signal(), std::nullopt);
}

TEST_F(childproc, terminate)
{
  auto child = create_child(TEST_BIN_SLOW, true);
  ASSERT_TRUE(bool(child));

  ASSERT_TRUE(bool((*child)->run()));
  ASSERT_TRUE(bool((*child)->terminate()));
  ASSERT_TRUE(bool((*child)->wait(100)));
  EXPECT_FALSE((*child)->is_alive());
  EXPECT_EQ((*child)->term_signal(), SIGTERM);
}

TEST_F(childproc, destructor_destroy_child)
{
  pid_t child_pid = 0;
  {
    auto child = create_child(TEST_BIN_SLOW, true);
    ASSERT_TRUE(bool(child));
    ASSERT_TRUE(bool((*child)->run()));
    child_pid = (*child)->pid();
    // Give child a little bit of time to execve before we kill it
    ASSERT_TRUE(bool((*child)->wait(25)));
  }

  int status = 0;
  pid_t ret = waitpid(child_pid, &status, WNOHANG);
  if (ret == -1 && errno == ECHILD)
    return;

  FAIL() << "Child should've been killed but appears to be alive: ret: " << ret
         << ", errno: " << errno << ", status: " << status << std::endl;
}

TEST_F(childproc, child_kill_before_exec)
{
  signal(SIGHUP, SIG_DFL);
  auto child = create_child(TEST_BIN_SLOW, true);
  ASSERT_TRUE(bool(child));

  EXPECT_EQ(kill((*child)->pid(), SIGHUP), 0);
  ASSERT_TRUE(bool((*child)->wait(100)));

  EXPECT_FALSE((*child)->is_alive());
  EXPECT_EQ((*child)->exit_code(), std::nullopt);
  EXPECT_EQ((*child)->term_signal(), SIGHUP);
}

TEST_F(childproc, stop_cont)
{
  // STOP/CONT should not incorrectly mark the child
  // as dead
  auto child = create_child(TEST_BIN_SLOW, true);
  ASSERT_TRUE(bool(child));
  int status = 0;

  ASSERT_TRUE(bool((*child)->run()));
  ASSERT_TRUE(bool((*child)->wait(25)));
  EXPECT_TRUE((*child)->is_alive());

  if (kill((*child)->pid(), SIGSTOP))
    FAIL() << "kill(SIGSTOP)";

  waitpid((*child)->pid(), &status, WUNTRACED);
  if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP)
    FAIL() << "! WIFSTOPPED";

  EXPECT_TRUE((*child)->is_alive());

  if (kill((*child)->pid(), SIGCONT))
    FAIL() << "kill(SIGCONT)";

  waitpid((*child)->pid(), &status, WCONTINUED);
  if (!WIFCONTINUED(status))
    FAIL() << "! WIFCONTINUED";

  EXPECT_TRUE((*child)->is_alive());

  ASSERT_TRUE(bool((*child)->terminate()));
  ASSERT_TRUE(bool((*child)->wait(100)));
  EXPECT_EQ((*child)->exit_code(), std::nullopt);
  EXPECT_EQ((*child)->term_signal(), SIGTERM);
}

TEST_F(childproc, ptrace_child_exit_success)
{
  auto child = create_child(TEST_BIN, true);
  ASSERT_TRUE(bool(child));

  ASSERT_TRUE(bool((*child)->run(true)));
  ASSERT_TRUE(bool((*child)->resume()));
  ASSERT_TRUE(bool((*child)->wait(1000)));
  EXPECT_FALSE((*child)->is_alive());
  EXPECT_EQ((*child)->exit_code(), 0);
  EXPECT_EQ((*child)->term_signal(), std::nullopt);
}

TEST_F(childproc, ptrace_child_exit_error)
{
  auto child = create_child(TEST_BIN_ERR, true);
  ASSERT_TRUE(bool(child));

  ASSERT_TRUE(bool((*child)->run(true)));
  ASSERT_TRUE(bool((*child)->resume()));
  ASSERT_TRUE(bool((*child)->wait(1000)));
  EXPECT_FALSE((*child)->is_alive());
  EXPECT_TRUE((*child)->exit_code().value_or(0) > 0);
  EXPECT_EQ((*child)->term_signal(), std::nullopt);
}

TEST_F(childproc, ptrace_child_kill_before_execve)
{
  auto child = create_child(TEST_BIN, true);
  ASSERT_TRUE(bool(child));

  ASSERT_TRUE(bool((*child)->run(true)));
  ASSERT_TRUE(bool((*child)->terminate(true)));
  ASSERT_TRUE(bool((*child)->wait(1000)));
  EXPECT_FALSE((*child)->is_alive());
  EXPECT_EQ((*child)->exit_code(), std::nullopt);
  EXPECT_EQ((*child)->term_signal(), 9);
}

TEST_F(childproc, ptrace_child_term_before_execve)
{
  auto child = create_child(TEST_BIN, true);
  ASSERT_TRUE(bool(child));

  ASSERT_TRUE(bool((*child)->run(true)));
  ASSERT_TRUE(bool((*child)->terminate()));
  ASSERT_TRUE(bool((*child)->wait(1000)));
  EXPECT_FALSE((*child)->is_alive());
  EXPECT_EQ((*child)->exit_code(), std::nullopt);
  EXPECT_EQ((*child)->term_signal(), 15);
}

TEST_F(childproc, multi_exec_match)
{
  std::error_code ec;

  // Create directory for test
  std::string tmpdir = "/tmp/bpftrace-test-child-XXXXXX";
  ASSERT_NE(::mkdtemp(tmpdir.data()), nullptr);

  // Create fixture directories
  const auto path = std::filesystem::path(tmpdir);
  const auto usr_bin = path / "usr" / "bin";
  ASSERT_TRUE(std::filesystem::create_directories(usr_bin, ec));
  ASSERT_FALSE(ec);

  // Create symbolic link: bin -> usr/bin
  const auto symlink_bin = path / "bin";
  std::filesystem::create_directory_symlink(usr_bin, symlink_bin, ec);
  ASSERT_FALSE(ec);

  // Copy a 'mysleep' binary and add x permission
  const auto binary = usr_bin / "mysleep";
  {
    std::ifstream src;
    std::ofstream dst;

    src.open(TEST_BIN_SLOW, std::ios::in | std::ios::binary);
    dst.open(binary, std::ios::out | std::ios::binary);
    dst << src.rdbuf();
    src.close();
    dst.close();

    EXPECT_EQ(::chmod(binary.c_str(), 0755), 0);
  }

  // Set ENV
  auto *old_path = ::getenv("PATH");
  auto new_path = usr_bin.native(); // copy
  new_path += ":";
  new_path += symlink_bin.c_str();
  EXPECT_EQ(::setenv("PATH", new_path.c_str(), 1), 0);

  // Use the filename with ambiguity.
  auto child = create_child(std::string(binary.filename()), true);
  ASSERT_TRUE(bool(child));

  ASSERT_TRUE(bool((*child)->run()));
  ASSERT_TRUE(bool((*child)->terminate()));
  ASSERT_TRUE(bool((*child)->wait(100)));
  EXPECT_FALSE((*child)->is_alive());
  EXPECT_EQ((*child)->term_signal(), SIGTERM);

  // Cleanup
  EXPECT_EQ(::setenv("PATH", old_path, 1), 0);
  EXPECT_GT(std::filesystem::remove_all(tmpdir), 0);
}

} // namespace bpftrace::test::child
