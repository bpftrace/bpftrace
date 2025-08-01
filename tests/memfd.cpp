#include <span>
#include <sys/stat.h>
#include <unistd.h>

#include "util/memfd.h"
#include "gtest/gtest.h"

namespace bpftrace::test::memfd {

using util::MemFd;

TEST(util, memfd_create_default_name)
{
  auto memfd = MemFd::create("test");
  ASSERT_TRUE(bool(memfd));
  EXPECT_FALSE(memfd->path().empty());
  EXPECT_TRUE(memfd->path().starts_with("/dev/fd/"));
}

TEST(util, memfd_write_and_read)
{
  auto memfd = MemFd::create("test_write_read");
  ASSERT_TRUE(bool(memfd));

  std::string test_data = "Hello, World!";
  std::span<const char> data_span(test_data.data(), test_data.size());

  auto write_result = memfd->write_all(data_span);
  ASSERT_TRUE(bool(write_result));

  auto read_data = memfd->read_all();
  ASSERT_TRUE(bool(read_data));
  EXPECT_EQ(*read_data, test_data);
}

TEST(util, memfd_write_large_data)
{
  auto memfd = MemFd::create("test_large");
  ASSERT_TRUE(bool(memfd));

  std::string large_data(1024 * 1024, 'A');
  std::span<const char> data_span(large_data.data(), large_data.size());

  auto write_result = memfd->write_all(data_span);
  ASSERT_TRUE(bool(write_result));

  auto read_data = memfd->read_all();
  ASSERT_TRUE(bool(read_data));
  EXPECT_EQ(read_data->size(), large_data.size());
  EXPECT_EQ(*read_data, large_data);
}

} // namespace bpftrace::test::memfd
