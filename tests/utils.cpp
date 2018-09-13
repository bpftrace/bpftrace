#include "gtest/gtest.h"

#include "utils-inl.h"

namespace bpftrace {
namespace test {

TEST(utils, provider_name_from_path)
{
  EXPECT_EQ(GetProviderFromPath("/path/to/binary"), "binary");
}

TEST(ast, provider_name_from_path)
{
  EXPECT_EQ(GetProviderFromPath("provider"), "provider");
}

} // namespace test
} // namespace bpftrace
