#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include <ctime>

#include "child.h"
#include "procmon.h"

#include "childhelper.h"
#include "utils.h"

namespace bpftrace::test::procmon {

using ::testing::HasSubstr;

TEST(procmon, no_such_proc)
{
  try {
    // NOLINTNEXTLINE(bugprone-unused-raii)
    ProcMon(1 << 21);
    FAIL();
  } catch (const std::runtime_error &e) {
    EXPECT_THAT(e.what(), HasSubstr("No such process"));
  }
}

TEST(procmon, child_terminates)
{
  std::error_code ec;
  auto self = std::filesystem::read_symlink("/proc/self/exe", ec);
  ASSERT_FALSE(ec);
  auto parent_dir = self.parent_path();
  auto out = parent_dir / std::filesystem::path("testprogs/true");
  auto child = getChild(out.c_str());
  auto procmon = std::make_unique<ProcMon>(child->pid());
  EXPECT_TRUE(procmon->is_alive());
  child->run();
  wait_for(child.get(), 1000);
  EXPECT_FALSE(child->is_alive());
  EXPECT_FALSE(procmon->is_alive());
  EXPECT_FALSE(procmon->is_alive());
}

} // namespace bpftrace::test::procmon
