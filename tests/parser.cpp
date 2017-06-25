#include "gtest/gtest.h"
#include "driver.h"

namespace bpftrace {

TEST(Parser, test0)
{
  Driver driver;
  std::string s = "kprobe:sys_open { @x = 1; }";
  EXPECT_EQ(driver.parse_str(s), 0);
}

TEST(Parser, test1)
{
  Driver driver;
  std::string s = "kprobe:sys_open { @x = 1; }";
  EXPECT_EQ(driver.parse_str(s), 0);
}

} // namespace bpftrace
