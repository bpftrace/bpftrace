#include <iostream>

#include "log.h"
#include "gtest/gtest.h"

namespace bpftrace::test::log {

TEST(LogStream, basic)
{
  std::ostringstream ss;
  const std::string content_1 = "hello world";
  const std::string content_2 = "some messages 100###**";

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
  ENABLE_LOG(V1);
  auto cerr_buf = std::cerr.rdbuf(ss.rdbuf());
  LOG(V1) << content_1 << content_2;
  EXPECT_EQ(ss.str(), content_1 + content_2 + "\n");
  std::cerr.rdbuf(cerr_buf);
  DISABLE_LOG(V1);
}

TEST(LogStream, basic_colorized)
{
  std::ostringstream ss;
  const std::string content_1 = "hello world";
  const std::string content_2 = "some messages 100###**";

  const std::string warning_color = std::string(bpftrace::LogColor::YELLOW);
  const std::string error_color = std::string(bpftrace::LogColor::RED);
  const std::string default_color = std::string(bpftrace::LogColor::RESET);

  Log::get().set_colorize(true);

  LOG(WARNING, ss) << content_1 << content_2;
  EXPECT_EQ(ss.str(),
            warning_color + "WARNING: " + content_1 + content_2 +
                default_color + "\n");
  ss.str({});

  LOG(ERROR, ss) << content_1 << content_2 << content_1 << content_2 << "\n"
                 << content_1 << content_2 << content_1 << content_2 << "\n";
  const std::string content_long = content_1 + content_2 + content_1 +
                                   content_2;
  EXPECT_EQ(ss.str(),
            error_color + "ERROR: " + content_long + "\n" + content_long +
                "\n" + default_color + "\n");

  Log::get().set_colorize(false);
  ss.str({});

  // test macro with 1 argument
  ENABLE_LOG(V1);
  auto cerr_buf = std::cerr.rdbuf(ss.rdbuf());
  LOG(V1) << content_1 << content_2;
  EXPECT_EQ(ss.str(), content_1 + content_2 + "\n");
  std::cerr.rdbuf(cerr_buf);
  DISABLE_LOG(V1);
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

TEST(LogStream, with_location_colorized)
{
  std::ostringstream ss;
  const std::string filename = "stdin";
  const std::string source = "i:s:1 { print(1, 2); }";
  const std::string error_msg =
      "stdin:1:9-20: ERROR: Non-map print() only takes 1 argument, 2 found\n";
  const std::string source_marker =
      "i:s:1 { print(1, 2); }\n        ~~~~~~~~~~~";

  const std::string error_color = std::string(bpftrace::LogColor::RED);
  const std::string default_color = std::string(bpftrace::LogColor::RESET);

  const std::string expected = error_color + error_msg + default_color +
                               source_marker + "\n";

  bpftrace::location loc(bpftrace::position(nullptr, 1, 9),
                         bpftrace::position(nullptr, 1, 20));
  Log::get().set_source(filename, source);
  Log::get().set_colorize(true);
  LOG(ERROR, loc, ss) << "Non-map print() only takes 1 argument, 2 found";
  Log::get().set_colorize(false);
  EXPECT_EQ(ss.str(), expected);
}

TEST(LogStream, with_location_colorized_multi_lines)
{
  std::ostringstream ss;
  const std::string filename = "stdin";
  const std::string source = "i:s:1 { print(1,\n 2, \n 3); }";
  const std::string error_msg =
      "stdin:1-3: ERROR: Non-map print() only takes 1 argument, 3 found";

  const std::string error_color = std::string(bpftrace::LogColor::RED);
  const std::string default_color = std::string(bpftrace::LogColor::RESET);

  const std::string expected = error_color + error_msg + "\n" + default_color;

  bpftrace::location loc(bpftrace::position(nullptr, 1),
                         bpftrace::position(nullptr, 3));
  Log::get().set_source(filename, source);
  Log::get().set_colorize(true);
  LOG(ERROR, loc, ss) << "Non-map print() only takes 1 argument, 3 found";
  Log::get().set_colorize(false);
  EXPECT_EQ(ss.str(), expected);
}

TEST(Log, disable_log_type)
{
  std::ostringstream ss;
  const std::string content = "This is the warning message";
  LOG(WARNING, ss) << content;
  EXPECT_EQ(ss.str(), "WARNING: " + content + "\n");
  ss.str({});
  Log::get().disable(LogType::WARNING);
  LOG(WARNING, ss) << content;
  EXPECT_EQ(ss.str(), "");
  // make sure other log types are not affected
  LOG(ERROR, ss) << content;
  EXPECT_EQ(ss.str(), "ERROR: " + content + "\n");
  ss.str({});
  Log::get().enable(LogType::WARNING);
  LOG(WARNING, ss) << content;
  EXPECT_EQ(ss.str(), "WARNING: " + content + "\n");
  ss.str({});
}

} // namespace bpftrace::test::log
