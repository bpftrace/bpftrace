#include "log.h"
#include "mocks.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include <iostream>

namespace bpftrace {
namespace test {
namespace log {

TEST(LogStream, basic)
{
  std::ostringstream ss;
  const std::string content_1 = "hello world";
  const std::string content_2 = "some messages 100###**";

  // clang-format off
  LOG(DEBUG, ss) << content_1; std::string file = __FILE__; int line = __LINE__;
  // clang-format on
  std::string prefix = "[" + file + ":" + std::to_string(line) + "]\n";
  EXPECT_EQ(ss.str(), "DEBUG: " + prefix + content_1 + "\n");
  ss.str({});

  LOG(WARNING, ss) << content_1 << content_2;
  EXPECT_EQ(ss.str(), "WARNING: " + content_1 + content_2 + "\n");
  ss.str({});

  LOG(ERROR, ss) << content_1 << content_2 << content_1 << content_2 << "\n"
                 << content_1 << content_2 << content_1 << content_2 << "\n";
  const std::string content_long = content_1 + content_2 + content_1 +
                                   content_2;
  EXPECT_EQ(ss.str(), "ERROR: " + content_long + "\n" + content_long + "\n\n");
  ss.str({});

  // test macro with 1 argument
  auto cerr_buf = std::cerr.rdbuf(ss.rdbuf());
  LOG(INFO) << content_1 << content_2;
  EXPECT_EQ(ss.str(), "INFO: " + content_1 + content_2 + "\n");
  std::cerr.rdbuf(cerr_buf);
}

TEST(LogStream, with_location)
{
  std::ostringstream ss;
  const std::string filename = "stdin";
  const std::string source = "i:s:1 { print(1, 2); }";
  const std::string expected =
      "stdin:1:9-20: ERROR: Non-map print() only takes 1 argument, 2 "
      "found\ni:s:1 { print(1, 2); }\n        ~~~~~~~~~~~\n";
  bpftrace::location loc(bpftrace::position(nullptr, 1, 9),
                         bpftrace::position(nullptr, 1, 20));
  Log::get().set_source(filename, source);
  LOG(ERROR, loc, ss) << "Non-map print() only takes 1 argument, 2 found";
  EXPECT_EQ(ss.str(), expected);
}

} // namespace log
} // namespace test
} // namespace bpftrace