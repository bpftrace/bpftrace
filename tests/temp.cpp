#include <sys/stat.h>
#include <unistd.h>

#include "util/temp.h"
#include "gtest/gtest.h"

namespace bpftrace::test::types {

using util::TempFile;

TEST(util, tempfile_no_pattern)
{
  std::string path;
  {
    auto f = TempFile::create();
    ASSERT_TRUE(bool(f));
    path = f->path().string();
    EXPECT_FALSE(path.empty());
    EXPECT_EQ(access(path.c_str(), F_OK), 0);
  }
  EXPECT_NE(access(path.c_str(), F_OK), 0);
}

TEST(util, tempfile_bad_pattern)
{
  auto f = TempFile::create("missingX");
  ASSERT_FALSE(bool(f));
}

TEST(util, tempfile_good_pattern)
{
  auto f1 = TempFile::create("testing.XXXXXX");
  auto f2 = TempFile::create("testing.XXXXXX");
  ASSERT_TRUE(bool(f1));
  ASSERT_TRUE(bool(f2));
  EXPECT_TRUE(f1->path().filename().string().starts_with("testing."));
  EXPECT_TRUE(f2->path().filename().string().starts_with("testing."));
}

} // namespace bpftrace::test::types
