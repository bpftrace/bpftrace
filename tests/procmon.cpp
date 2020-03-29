#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include <time.h>

#include "child.h"
#include "procmon.h"

#include "childhelper.h"

namespace bpftrace {
namespace test {
namespace procmon {

using ::testing::HasSubstr;

TEST(procmon, no_such_proc)
{
  try
  {
    ProcMon(1 << 21);
    FAIL();
  }
  catch (const std::runtime_error &e)
  {
    EXPECT_THAT(e.what(), HasSubstr("No such process"));
  }
}

TEST(procmon, child_terminates)
{
  auto child = getChild("/bin/ls");
  auto procmon = std::make_unique<ProcMon>(child->pid());
  EXPECT_TRUE(procmon->is_alive());
  child->run();
  wait_for(child.get(), 1000);
  EXPECT_FALSE(child->is_alive());
  EXPECT_FALSE(procmon->is_alive());
  EXPECT_FALSE(procmon->is_alive());
}

TEST(procmon, pid_string)
{
  auto child = getChild("/bin/ls");
  auto procmon = std::make_unique<ProcMon>(std::to_string(child->pid()));
  EXPECT_TRUE(procmon->is_alive());
}

} // namespace procmon
} // namespace test
} // namespace bpftrace
