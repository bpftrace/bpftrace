#include "async_action.h"
#include "ast/async_event_types.h"
#include "bpftrace.h"
#include "location.hh"
#include "mocks.h"
#include "types.h"
#include "util/exceptions.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace bpftrace::test::async_action {

using namespace bpftrace::async_action;

template <typename... Args>
void syscall_proxy(std::unique_ptr<MockBPFtrace> &bpftrace,
                   std::string &command,
                   Args... args)
{
  FormatString cmd(command);
  std::vector<Field> fields;
  size_t total_args_size = 0;
  const char *arg_strs[] = { args... };

  if constexpr (sizeof...(Args) > 0) {
    ssize_t offset = sizeof(uint64_t);
    for (const char *arg_str : arg_strs) {
      size_t arg_len = strlen(arg_str) + 1;
      fields.push_back(Field{ .name = "arg",
                              .type = CreateString(arg_len),
                              .offset = offset,
                              .bitfield = std::nullopt });
      offset += arg_len;
      total_args_size += arg_len;
    }
  }

  bpftrace->resources.system_args.emplace_back(std::make_tuple(cmd, fields));
  uint64_t printf_id = static_cast<uint64_t>(AsyncAction::syscall);
  size_t data_size = sizeof(uint64_t) + total_args_size;
  std::vector<uint8_t> arg_data(data_size, 0);
  memcpy(arg_data.data(), &printf_id, sizeof(printf_id));
  if constexpr (sizeof...(Args) > 0) {
    ssize_t offset = sizeof(uint64_t);

    for (const char *arg_str : arg_strs) {
      size_t arg_len = strlen(arg_str) + 1;
      memcpy(arg_data.data() + offset, arg_str, arg_len);
      offset += arg_len;
    }
  }

  syscall_handler(bpftrace.get(), AsyncAction::syscall, arg_data.data());
}

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

TEST(async_action, helper_error)
{
  struct TestCase {
    int func_id;
    int return_value;
    std::string expected_substring;
    std::string filename;
    unsigned int line;
    unsigned int column;
  };

  std::vector<TestCase> test_cases = {
    // case 1: `map_update_elem` returns `-E2BIG`
    { .func_id = libbpf::BPF_FUNC_map_update_elem,
      .return_value = -E2BIG,
      .expected_substring = "WARNING: Map full; can't update element",
      .filename = std::string("test1.bt"),
      .line = 10,
      .column = 5 },
    // case 2: `map_delete_elem` returns `-ENOENT`
    { .func_id = libbpf::BPF_FUNC_map_delete_elem,
      .return_value = -ENOENT,
      .expected_substring =
          "WARNING: Can't delete map element because it does not exist",
      .filename = std::string("test2.bt"),
      .line = 15,
      .column = 8 },
    // case 3: `map_lookup_elem` failed to lookup map element
    { .func_id = libbpf::BPF_FUNC_map_lookup_elem,
      .return_value = 0,
      .expected_substring =
          "WARNING: Can't lookup map element because it does not exist",
      .filename = std::string("test3.bt"),
      .line = 20,
      .column = 3 },
    // case 4: default case - other function ID and error code
    { .func_id = libbpf::BPF_FUNC_trace_printk,
      .return_value = -EPERM,
      .expected_substring = "WARNING: " + std::string(strerror(EPERM)),
      .filename = std::string("test4.bt"),
      .line = 25,
      .column = 1 }
  };

  for (const auto &tc : test_cases) {
    std::stringstream out;
    auto bpftrace = get_mock_bpftrace(out);

    auto src_loc = ast::SourceLocation(
        location(&tc.filename, tc.line, tc.column));
    auto location_chain = std::make_shared<ast::LocationChain>(src_loc);
    HelperErrorInfo info(tc.func_id, location_chain);

    bpftrace->resources.helper_error_info.emplace(tc.func_id, std::move(info));

    AsyncEvent::HelperError error_event(static_cast<int64_t>(
                                            AsyncAction::helper_error),
                                        tc.func_id,
                                        tc.return_value);

    helper_error_handler(bpftrace.get(), &error_event);

    std::string output = out.str();
    EXPECT_THAT(output, testing::HasSubstr(tc.expected_substring))
        << "function: " << tc.func_id << " return " << tc.return_value
        << " failed";

    std::string expected_loc = std::to_string(tc.line) + ":" +
                               std::to_string(tc.column);
    EXPECT_THAT(output, testing::HasSubstr(expected_loc))
        << "Source location not found in output: " << expected_loc;

    EXPECT_THAT(output, testing::HasSubstr(std::to_string(tc.return_value)))
        << "Return value not found in output: " << tc.return_value;
  }
}

TEST(async_action, syscall)
{
  std::stringstream out;
  auto bpftrace = get_mock_bpftrace(out);
  bpftrace->safe_mode_ = false;
  auto cmd = std::string("echo test");

  syscall_proxy(bpftrace, cmd);

  EXPECT_THAT(out.str(), testing::HasSubstr("test"))
      << "Syscall output should contain the result of 'echo test'";
}

TEST(async_action, syscall_safe_mode)
{
  std::stringstream out;
  auto bpftrace = get_mock_bpftrace(out);
  auto cmd = std::string("echo test");

  try {
    syscall_proxy(bpftrace, cmd);
    FAIL() << "Expected syscall_handler to throw an exception in safe mode";
  } catch (const util::FatalUserException &ex) {
    EXPECT_THAT(std::string(ex.what()),
                testing::HasSubstr(
                    "syscall() not allowed in safe mode. Use '--unsafe'."))
        << "Exception should indicate syscall is not allowed in safe mode";
  } catch (...) {
    FAIL() << "Expected syscall_handler to throw a FatalUserException in safe "
              "mode";
  }

  EXPECT_TRUE(out.str().empty())
      << "No output should be generated in safe mode";
}

TEST(async_action, syscall_with_args)
{
  std::stringstream out;
  auto bpftrace = get_mock_bpftrace(out);
  bpftrace->safe_mode_ = false;
  auto cmd = std::string("echo %s");

  syscall_proxy(bpftrace, cmd, "hello world");

  EXPECT_THAT(out.str(), testing::HasSubstr("hello world"))
      << "Syscall output should contain the argument 'hello world'";
}

} // namespace bpftrace::test::async_action
