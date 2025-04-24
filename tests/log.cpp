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
  EXPECT_EQ(ss.str(), "ERROR: " + content_long + "\n" + content_long + "\n");
  ss.str({});

  // test macro with 1 argument
  ENABLE_LOG(V1);
  auto *cerr_buf = std::cerr.rdbuf(ss.rdbuf());
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
                default_color + "\n");

  Log::get().set_colorize(false);
  ss.str({});

  // test macro with 1 argument
  ENABLE_LOG(V1);
  auto *cerr_buf = std::cerr.rdbuf(ss.rdbuf());
  LOG(V1) << content_1 << content_2;
  EXPECT_EQ(ss.str(), content_1 + content_2 + "\n");
  std::cerr.rdbuf(cerr_buf);
  DISABLE_LOG(V1);
}

TEST(LogStream, with_location)
{
  std::string location = "stdin:xyz";
  std::vector<std::string> context({ "ctx1", "ctx2" });

  std::ostringstream ss;
  const std::string expected = "stdin:xyz: ERROR: test error\n"
                               "ctx1\n"
                               "ctx2\n";
  LOG(ERROR, std::move(location), std::move(context), ss) << "test error";
  EXPECT_EQ(ss.str(), expected);
}

TEST(LogStream, with_location_colorized)
{
  std::string location = "stdin:xyz";
  std::vector<std::string> context({ "ctx1", "ctx2" });

  std::ostringstream ss;
  const std::string error_color = std::string(bpftrace::LogColor::RED);
  const std::string default_color = std::string(bpftrace::LogColor::RESET);

  const std::string expected = error_color + "stdin:xyz: ERROR: test error" +
                               default_color + "\n" + "ctx1\n" + "ctx2\n";
  Log::get().set_colorize(true);
  LOG(ERROR, std::move(location), std::move(context), ss) << "test error";
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

TEST(LogBugStream, log_bug_should_be_aborted)
{
  const std::string content = "I'm gonna die";

  auto output = [&content](int line) {
    const std::string filename = __FILE__;
    return "BUG: \\[" + filename + ":" + std::to_string(line) + "\\] " +
           content;
  };
  EXPECT_DEATH(LOG(BUG) << content, output(__LINE__));
}

} // namespace bpftrace::test::log
