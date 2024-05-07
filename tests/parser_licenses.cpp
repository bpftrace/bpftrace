#include <optional>
#include <string>
#include <string_view>

#include "bpftrace.h"
#include "driver.h"
#include "gtest/gtest.h"

namespace bpftrace::test::parser_licenses {

void test(std::string_view input, std::optional<std::string> expected_license)
{
  BPFtrace bpftrace;
  Driver driver{ bpftrace };
  ASSERT_EQ(0, driver.parse_str(input));
  EXPECT_EQ(expected_license,
            bpftrace.config_.try_get(ConfigKeyString::license));
}

TEST(ParserLicenses, GPL_v2_only)
{
  test(R"(
// SPDX-License-Identifier: GPL-2.0-only
BEGIN {}
)",
       "GPL");
}

TEST(ParserLicenses, GPL_v2_or_later)
{
  test(R"(
// SPDX-License-Identifier: GPL-2.0-or-later
BEGIN {}
)",
       "GPL");
}

TEST(ParserLicenses, GPL_v1)
{
  test(R"(
// SPDX-License-Identifier: GPL-1.0-only
BEGIN {}
)",
       "GPL-1.0-only");
}

TEST(ParserLicenses, GPL_v3)
{
  test(R"(
// SPDX-License-Identifier: GPL-3.0-only
BEGIN {}
)",
       "GPL-3.0-only");
}

TEST(ParserLicenses, Apache_2)
{
  test(R"(
// SPDX-License-Identifier: Apache-2.0
BEGIN {}
)",
       "Apache-2.0");
}

} // namespace bpftrace::test::parser_licenses
