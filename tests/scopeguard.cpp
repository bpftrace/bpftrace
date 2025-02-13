#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "scopeguard.h"

#include <exception>

namespace bpftrace {

TEST(ScopeGuardTest, InnerScope)
{
  int x = 5;

  {
    SCOPE_EXIT
    {
      x++;
    };
  }

  EXPECT_EQ(x, 6);
}

TEST(ScopeGuardTest, FunctionReturn)
{
  int x = 5;

  [&]() {
    SCOPE_EXIT
    {
      x++;
    };

    x++;
    return;
  }();

  EXPECT_EQ(x, 7);
}

TEST(ScopeGuardTest, ExceptionContext)
{
  int x = 5;

  try {
    [&]() {
      SCOPE_EXIT
      {
        x++;
      };

      throw std::runtime_error("exception");
    }();
  } catch (const std::exception &) {
    EXPECT_EQ(x, 6);
    x++;
  }

  EXPECT_EQ(x, 7);
}

TEST(ScopeGuardTest, MultipleGuards)
{
  int x = 5;

  {
    SCOPE_EXIT
    {
      x++;
    };

    SCOPE_EXIT
    {
      x++;
    };
  }

  EXPECT_EQ(x, 7);
}

} // namespace bpftrace
