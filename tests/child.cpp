#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include <sstream>
#include <string>

#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "child.h"
#include "childhelper.h"
#include "utils.h"

namespace bpftrace {
namespace test {
namespace child {

using ::testing::HasSubstr;

#define TEST_BIN "/bin/ls"
#define TEST_BIN_ERR "/bin/ls /does/not/exist/abc"
#define TEST_BIN_SLOW "/bin/sleep 10"

TEST(childproc, exe_does_not_exist)
{
  try
  {
    ChildProc child("/does/not/exist/abc/fed");
    FAIL();
  }
  catch (const std::runtime_error &e)
  {
    EXPECT_THAT(e.what(), HasSubstr("does not exist or is not executable"));
  }
}

TEST(childproc, too_many_arguments)
{
  std::stringstream cmd;
  cmd << "/bin/ls";
  for (int i = 0; i < 280; i++)
    cmd << " a";

  try
  {
    ChildProc child(cmd.str());
    FAIL();
  }
  catch (const std::runtime_error &e)
  {
    EXPECT_THAT(e.what(), HasSubstr("Too many arguments"));
  }
}

TEST(childproc, child_exit_success)
{
  // Spawn a child that exits successfully
  auto child = getChild(TEST_BIN);

  child->run();
  wait_for(child.get(), 1000);
  EXPECT_FALSE(child->is_alive());
  EXPECT_EQ(child->exit_code(), 0);
  EXPECT_EQ(child->term_signal(), -1);
}

TEST(childproc, child_exit_err)
{
  // Spawn a child that exits with an error
  auto child = getChild(TEST_BIN_ERR);

  child->run();
  wait_for(child.get(), 1000);
  EXPECT_FALSE(child->is_alive());
  EXPECT_TRUE(child->exit_code() > 0);
  EXPECT_EQ(child->term_signal(), -1);
}

TEST(childproc, terminate)
{
  auto child = getChild(TEST_BIN_SLOW);

  child->run();
  child->terminate();
  wait_for(child.get(), 100);
  EXPECT_FALSE(child->is_alive());
  EXPECT_EQ(child->term_signal(), SIGTERM);
}

TEST(childproc, destructor_destroy_child)
{
  pid_t child_pid = 0;
  {
    std::unique_ptr<ChildProc> child = getChild(TEST_BIN_SLOW);
    child->run();
    child_pid = child->pid();
    // Give child a little bit of time to execve before we kill it
    msleep(25);
  }

  int status = 0;
  pid_t ret = waitpid(child_pid, &status, WNOHANG);
  if (ret == -1 && errno == ECHILD)
    return;

  FAIL() << "Child should've been killed but appears to be alive: ret: " << ret
         << ", errno: " << errno << ", status: " << status << std::endl;
}

TEST(childproc, child_kill_before_exec)
{
  signal(SIGHUP, SIG_DFL);
  auto child = getChild(TEST_BIN_SLOW);

  EXPECT_EQ(kill(child->pid(), SIGHUP), 0);
  wait_for(child.get(), 100);

  EXPECT_FALSE(child->is_alive());
  EXPECT_EQ(child->exit_code(), -1);
  EXPECT_EQ(child->term_signal(), SIGHUP);
}

TEST(childproc, stop_cont)
{
  // STOP/CONT should not incorrectly mark the child
  // as dead
  auto child = getChild(TEST_BIN_SLOW);
  int status = 0;

  child->run();
  msleep(25);
  EXPECT_TRUE(child->is_alive());

  if (kill(child->pid(), SIGSTOP))
    FAIL() << "kill(SIGSTOP)";

  waitpid(child->pid(), &status, WUNTRACED);
  if (!(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP))
    FAIL() << "! WIFSTOPPED";

  EXPECT_TRUE(child->is_alive());

  if (kill(child->pid(), SIGCONT))
    FAIL() << "kill(SIGCONT)";

  waitpid(child->pid(), &status, WCONTINUED);
  if (!WIFCONTINUED(status))
    FAIL() << "! WIFCONTINUED";

  EXPECT_TRUE(child->is_alive());

  child->terminate();
  wait_for(child.get(), 100);
  EXPECT_EQ(child->exit_code(), -1);
  EXPECT_EQ(child->term_signal(), SIGTERM);
}

TEST(childproc, ptrace_child_exit_success)
{
  auto child = getChild(TEST_BIN);

  child->run(true);
  child->resume();
  wait_for(child.get(), 1000);
  EXPECT_FALSE(child->is_alive());
  EXPECT_EQ(child->exit_code(), 0);
  EXPECT_EQ(child->term_signal(), -1);
}

TEST(childproc, ptrace_child_exit_error)
{
  auto child = getChild(TEST_BIN_ERR);

  child->run(true);
  child->resume();
  wait_for(child.get(), 1000);
  EXPECT_FALSE(child->is_alive());
  EXPECT_TRUE(child->exit_code() > 0);
  EXPECT_EQ(child->term_signal(), -1);
}

TEST(childproc, ptrace_child_kill_before_execve)
{
  auto child = getChild(TEST_BIN);

  child->run(true);
  child->terminate(true);
  wait_for(child.get(), 1000);
  EXPECT_FALSE(child->is_alive());
  EXPECT_EQ(child->exit_code(), -1);
  EXPECT_EQ(child->term_signal(), 9);
}

TEST(childproc, ptrace_child_term_before_execve)
{
  auto child = getChild(TEST_BIN);

  child->run(true);
  child->terminate();
  wait_for(child.get(), 1000);
  EXPECT_FALSE(child->is_alive());
  EXPECT_EQ(child->exit_code(), -1);
  EXPECT_EQ(child->term_signal(), 15);
}

} // namespace child
} // namespace test
} // namespace bpftrace
