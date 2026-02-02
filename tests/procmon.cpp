#include <ctime>
#include <filesystem>

#include "util/proc.h"
#include "llvm/Support/Error.h"
#include "gmock/gmock-matchers.h"
#include "gtest/gtest.h"

namespace bpftrace::test::procmon {

using ::testing::HasSubstr;

TEST(procmon, no_such_proc)
{
  auto ok = util::create_proc(1 << 21);
  EXPECT_FALSE(bool(ok));
  EXPECT_THAT(llvm::toString(ok.takeError()), HasSubstr("No such process"));
}

TEST(procmon, child_terminates)
{
  std::error_code ec;
  auto self = std::filesystem::read_symlink("/proc/self/exe", ec);
  ASSERT_FALSE(ec);
  auto parent_dir = self.parent_path();
  auto out = parent_dir / std::filesystem::path("testprogs/true");
  auto child = util::create_child(out.string(), true);
  ASSERT_TRUE(bool(child));
  auto procmon = util::create_proc((*child)->pid());
  ASSERT_TRUE(bool(procmon));
  EXPECT_TRUE((*procmon)->is_alive());
  ASSERT_TRUE(bool((*child)->run()));
  ASSERT_TRUE(bool((*child)->wait(1000)));
  EXPECT_FALSE((*child)->is_alive());
  EXPECT_FALSE((*procmon)->is_alive());
}

} // namespace bpftrace::test::procmon
