#include "async_action.h"
#include "ast/async_event_types.h"
#include "bpftrace.h"
#include "mocks.h"
#include "types.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace bpftrace::test::async_action {

using namespace bpftrace::async_action;

TEST(async_action, join)
{
  std::stringstream out;
  auto bpftrace = get_mock_bpftrace(out);
  bpftrace->resources.join_args.emplace_back(",");

  unsigned int content_size = bpftrace->join_argsize_ * bpftrace->join_argnum_;
  size_t total_size = sizeof(AsyncEvent::Join) + content_size;
  char buffer[total_size];
  memset(buffer, 0, total_size);

  auto *join = reinterpret_cast<AsyncEvent::Join *>(buffer);
  auto action_id = static_cast<uint64_t>(AsyncAction::join);
  uint64_t join_id = 0;
  memcpy(&join->action_id, &action_id, sizeof(action_id));
  memcpy(&join->join_id, &join_id, sizeof(join_id));

  const char *arg1 = "/bin/ls";
  const char *arg2 = "-la";
  const char *arg3 = "/tmp";

  memcpy(join->content, arg1, strlen(arg1) + 1);
  memcpy(join->content + bpftrace->join_argsize_, arg2, strlen(arg2) + 1);
  memcpy(join->content + (2 * bpftrace->join_argsize_), arg3, strlen(arg3) + 1);

  join_handler(bpftrace.get(), join);
  EXPECT_EQ("/bin/ls,-la,/tmp\n", out.str());
}

TEST(async_action, time)
{
  std::stringstream out;
  auto bpftrace = get_mock_bpftrace(out);

  bpftrace->resources.time_args.emplace_back("%Y-%m-%d");
  bpftrace->resources.time_args.emplace_back("%H:%M:%S");
  bpftrace->resources.time_args.emplace_back("%a, %d %b %Y");

  // The first format
  {
    AsyncEvent::Time time_event(static_cast<int>(AsyncAction::time), 0);
    time_handler(bpftrace.get(), &time_event);

    std::regex pattern(R"(\d{4}-\d{2}-\d{2})");
    EXPECT_TRUE(std::regex_match(out.str(), pattern));
    out.str("");
  }

  // The second format
  {
    AsyncEvent::Time time_event(static_cast<int>(AsyncAction::time), 1);
    time_handler(bpftrace.get(), &time_event);

    std::regex pattern(R"(\d{2}:\d{2}:\d{2})");
    EXPECT_TRUE(std::regex_match(out.str(), pattern));
    out.str("");
  }

  // The third format
  {
    AsyncEvent::Time time_event(static_cast<int>(AsyncAction::time), 2);
    time_handler(bpftrace.get(), &time_event);

    std::regex pattern(R"([A-Za-z]+, \d{2} [A-Za-z]+ \d{4})");
    EXPECT_TRUE(std::regex_match(out.str(), pattern));
  }
}

TEST(async_action, time_invalid_format)
{
  std::stringstream out;
  auto bpftrace = get_mock_bpftrace(out);

  // invalid time format string
  std::string very_long_format(bpftrace::async_action::MAX_TIME_STR_LEN, 'X');
  very_long_format = "%Y-%m-%d " + very_long_format;
  bpftrace->resources.time_args.emplace_back(very_long_format);
  AsyncEvent::Time time_event(static_cast<int>(AsyncAction::time), 0);

  testing::internal::CaptureStderr();

  time_handler(bpftrace.get(), &time_event);
  EXPECT_TRUE(out.str().empty());

  std::string log = testing::internal::GetCapturedStderr();

  EXPECT_THAT(log, testing::HasSubstr("strftime returned 0"));
}

} // namespace bpftrace::test::async_action
