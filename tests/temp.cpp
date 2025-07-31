#include <sys/stat.h>
#include <unistd.h>

#include "util/temp.h"
#include "gtest/gtest.h"

namespace bpftrace::test::types {

using util::TempDir;
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

TEST(util, tempdir)
{
  auto d = TempDir::create();
  ASSERT_TRUE(bool(d));
  auto f1 = d->create_file("foo");
  auto f2 = d->create_file("bar");
  auto f3 = d->create_file();
  ASSERT_TRUE(bool(f1));
  ASSERT_TRUE(bool(f2));
  ASSERT_TRUE(bool(f3));
  EXPECT_TRUE(f1->path().filename().string().starts_with("foo."));
  EXPECT_TRUE(f2->path().filename().string().starts_with("bar."));
}

TEST(util, tempdir_no_pattern)
{
  auto d = TempDir::create();
  ASSERT_TRUE(bool(d));
  auto f1 = d->create_file("foo", false);
  auto f2 = d->create_file("bar", false);
  ASSERT_TRUE(bool(f1));
  ASSERT_TRUE(bool(f2));
  EXPECT_EQ(f1->path().filename().string(), "foo");
  EXPECT_EQ(f2->path().filename().string(), "bar");
  auto ok = d->create_file("foo", false);
  EXPECT_FALSE(bool(ok));
  auto nowOk = handleErrors(std::move(ok), [&](const SystemError &err) {
    EXPECT_EQ(err.err(), EEXIST);
  });
  EXPECT_TRUE(bool(nowOk));
}

} // namespace bpftrace::test::types
