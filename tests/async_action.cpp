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

// Process string type argument - handle const char*
template <typename T>
void process_arg(std::vector<Field> &fields,
                 ssize_t &offset,
                 size_t &total_size,
                 T arg,
                 [[maybe_unused]] std::enable_if_t<
                     std::is_convertible_v<T, const char *>> *unused = nullptr)
{
  const char *str = arg;
  size_t arg_len = strlen(str) + 1;

  fields.push_back(Field{ .name = "arg",
                          .type = CreateString(arg_len),
                          .offset = offset,
                          .bitfield = std::nullopt });

  offset += arg_len;
  total_size += arg_len;
}

// Process integer type argument
template <typename T>
void process_arg(std::vector<Field> &fields,
                 ssize_t &offset,
                 size_t &total_size,
                 [[maybe_unused]] T arg,
                 [[maybe_unused]] std::enable_if_t<std::is_integral_v<T> &&
                                                   !std::is_same_v<T, char *>>
                     *unused = nullptr)
{
  size_t arg_size = sizeof(T);

  fields.push_back(Field{ .name = "arg",
                          .type = CreateInt(arg_size * 8),
                          .offset = offset,
                          .bitfield = std::nullopt });

  offset += arg_size;
  total_size += arg_size;
}

template <typename T>
void fill_arg_data(
    uint8_t *data,
    ssize_t &offset,
    T arg,
    [[maybe_unused]] std::enable_if_t<std::is_convertible_v<T, const char *>>
        *unused = nullptr)
{
  const char *str = arg;
  size_t arg_len = strlen(str) + 1;
  memcpy(data + offset, str, arg_len);
  offset += arg_len;
}

// Fill data for integer, unsigned long long and char type arguments
template <typename T>
void fill_arg_data(
    uint8_t *data,
    ssize_t &offset,
    T arg,
    [[maybe_unused]] std::enable_if_t<!std::is_convertible_v<T, const char *> &&
                                      !std::is_same_v<T, std::string>> *unused =
        nullptr)
{
  memcpy(data + offset, &arg, sizeof(T));
  offset += sizeof(T);
}

template <AsyncAction id, typename... Args>
std::string handler_proxy(std::unique_ptr<MockBPFtrace> &bpftrace,
                          std::string &fmt_str,
                          [[maybe_unused]] Args... args)
{
  FormatString fmt(fmt_str);
  std::vector<Field> fields;
  size_t total_args_size = 0;

  if constexpr (sizeof...(Args) > 0) {
    ssize_t offset = sizeof(uint64_t);
    (process_arg(fields, offset, total_args_size, args), ...);
  }

  auto printf_id = static_cast<uint64_t>(id);
  size_t data_size = sizeof(uint64_t) + total_args_size;
  std::vector<uint8_t> arg_data(data_size, 0);
  memcpy(arg_data.data(), &printf_id, sizeof(printf_id));
  if constexpr (sizeof...(Args) > 0) {
    ssize_t offset = sizeof(uint64_t);
    (fill_arg_data(arg_data.data(), offset, args), ...);
  }

  CDefinitions no_c_defs;
  std::stringstream out;
  TextOutput output(no_c_defs, out);

  static_assert((id == AsyncAction::syscall || id == AsyncAction::cat ||
                 id == AsyncAction::printf) &&
                "Only support syscall, cat, and printf");
  if (id == AsyncAction::syscall) {
    bpftrace->resources.system_args.emplace_back(fmt, fields);
    syscall_handler(*bpftrace, output, id, arg_data.data());
  } else if (id == AsyncAction::cat) {
    bpftrace->resources.cat_args.emplace_back(fmt, fields);
    cat_handler(*bpftrace, output, id, arg_data.data());
  } else if (id == AsyncAction::printf) {
    bpftrace->resources.printf_args.emplace_back(fmt, fields);
    printf_handler(*bpftrace, output, id, arg_data.data());
  }

  return out.str();
}

TEST(async_action, join)
{
  auto bpftrace = get_mock_bpftrace();
  bpftrace->resources.join_args.emplace_back(",");

  unsigned int content_size = bpftrace->join_argsize_ * bpftrace->join_argnum_;
  size_t total_size = sizeof(AsyncEvent::Join) + content_size;
  char buffer[total_size];
  memset(buffer, 0, total_size);

  auto *join = reinterpret_cast<AsyncEvent::Join *>(buffer);
  join->action_id = static_cast<uint64_t>(AsyncAction::join);
  join->join_id = 0;

  const char *arg1 = "/bin/ls";
  const char *arg2 = "-la";
  const char *arg3 = "/tmp";

  memcpy(join->content, arg1, strlen(arg1) + 1);
  memcpy(join->content + bpftrace->join_argsize_, arg2, strlen(arg2) + 1);
  memcpy(join->content + (2 * bpftrace->join_argsize_), arg3, strlen(arg3) + 1);

  CDefinitions no_c_defs;
  std::stringstream out;
  TextOutput output(no_c_defs, out);

  join_handler(*bpftrace, output, join);
  EXPECT_EQ("/bin/ls,-la,/tmp\n", out.str());
}

TEST(async_action, time)
{
  auto bpftrace = get_mock_bpftrace();

  CDefinitions no_c_defs;
  std::stringstream out;
  TextOutput output(no_c_defs, out);

  bpftrace->resources.time_args.emplace_back("%Y-%m-%d");
  bpftrace->resources.time_args.emplace_back("%H:%M:%S");
  bpftrace->resources.time_args.emplace_back("%a, %d %b %Y");

  // The first format
  {
    AsyncEvent::Time time_event(static_cast<int>(AsyncAction::time), 0);
    time_handler(*bpftrace, output, &time_event);

    std::regex pattern(R"(\d{4}-\d{2}-\d{2})");
    EXPECT_TRUE(std::regex_match(out.str(), pattern));
    out.str("");
  }

  // The second format
  {
    AsyncEvent::Time time_event(static_cast<int>(AsyncAction::time), 1);
    time_handler(*bpftrace, output, &time_event);

    std::regex pattern(R"(\d{2}:\d{2}:\d{2})");
    EXPECT_TRUE(std::regex_match(out.str(), pattern));
    out.str("");
  }

  // The third format
  {
    AsyncEvent::Time time_event(static_cast<int>(AsyncAction::time), 2);
    time_handler(*bpftrace, output, &time_event);

    std::regex pattern(R"([A-Za-z]+, \d{2} [A-Za-z]+ \d{4})");
    EXPECT_TRUE(std::regex_match(out.str(), pattern));
  }
}

TEST(async_action, time_invalid_format)
{
  auto bpftrace = get_mock_bpftrace();

  CDefinitions no_c_defs;
  std::stringstream out;
  TextOutput output(no_c_defs, out);

  // invalid time format string
  std::string very_long_format(bpftrace::async_action::MAX_TIME_STR_LEN, 'X');
  very_long_format = "%Y-%m-%d " + very_long_format;
  bpftrace->resources.time_args.emplace_back(very_long_format);
  AsyncEvent::Time time_event(static_cast<int>(AsyncAction::time), 0);

  testing::internal::CaptureStderr();

  time_handler(*bpftrace, output, &time_event);
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
    auto bpftrace = get_mock_bpftrace();

    CDefinitions no_c_defs;
    std::stringstream out;
    TextOutput output(no_c_defs, out);

    auto src_loc = ast::SourceLocation(
        location(&tc.filename, tc.line, tc.column));
    auto location_chain = std::make_shared<ast::LocationChain>(src_loc);
    HelperErrorInfo info(tc.func_id, location_chain);

    bpftrace->resources.helper_error_info.emplace(tc.func_id, std::move(info));

    AsyncEvent::HelperError error_event(static_cast<int64_t>(
                                            AsyncAction::helper_error),
                                        tc.func_id,
                                        tc.return_value);

    helper_error_handler(*bpftrace, output, &error_event);

    auto s = out.str();
    EXPECT_THAT(s, testing::HasSubstr(tc.expected_substring))
        << "function: " << tc.func_id << " return " << tc.return_value
        << " failed";

    std::string expected_loc = std::to_string(tc.line) + ":" +
                               std::to_string(tc.column);
    EXPECT_THAT(s, testing::HasSubstr(expected_loc))
        << "Source location not found in output: " << expected_loc;

    EXPECT_THAT(s, testing::HasSubstr(std::to_string(tc.return_value)))
        << "Return value not found in output: " << tc.return_value;
  }
}

TEST(async_action, syscall)
{
  struct TestCase {
    std::string cmd;
    std::optional<const char *> args;
    std::string expected_substring;
  };

  std::vector<TestCase> test_cases = {
    { .cmd = std::string("echo test"),
      .args = std::nullopt,
      .expected_substring = "test" },
    { .cmd = std::string("echo %s"),
      .args = "test",
      .expected_substring = "test" },
  };

  for (auto &tc : test_cases) {
    auto bpftrace = get_mock_bpftrace();
    bpftrace->safe_mode_ = false;

    std::string out;
    if (tc.args.has_value()) {
      out = handler_proxy<AsyncAction::syscall>(bpftrace,
                                                tc.cmd,
                                                tc.args.value());
    } else {
      out = handler_proxy<AsyncAction::syscall>(bpftrace, tc.cmd);
    }

    EXPECT_THAT(out, testing::HasSubstr(tc.expected_substring))
        << "Syscall output should contain the result of 'echo test'";
  }
}

TEST(async_action, syscall_safe_mode)
{
  auto bpftrace = get_mock_bpftrace();
  auto cmd = std::string("echo test");

  std::string out;
  try {
    out = handler_proxy<AsyncAction::syscall>(bpftrace, cmd);
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

  EXPECT_TRUE(out.empty()) << "No output should be generated in safe mode";
}

TEST(async_action, cat)
{
  std::string test_content = "Hello, cat_handler test!\nThis is line 2.\n";
  char filename[] = "/tmp/bpftrace-test-cat-XXXXXX";
  int fd = mkstemp(filename);
  ASSERT_NE(fd, -1) << "Failed to create temporary file";
  ASSERT_EQ(write(fd, test_content.c_str(), test_content.length()),
            static_cast<ssize_t>(test_content.length()));
  close(fd);

  auto bpftrace = get_mock_bpftrace();
  bpftrace->config_->max_cat_bytes = 1024;

  auto cmd = std::string("%s/%s");
  std::string basename = std::string(filename).substr(5);
  std::string out = handler_proxy<AsyncAction::cat>(
      bpftrace, cmd, "/tmp", basename.c_str());

  EXPECT_EQ(test_content, out)
      << "cat_handler should output the file content correctly";

  std::remove(filename);
}

TEST(async_action, printf)
{
  auto bpftrace = get_mock_bpftrace();

  std::string format = "Multiple: %s=%d (0x%llx) char=%hhu";
  char expected_buffer[64];
  snprintf(expected_buffer,
           sizeof(expected_buffer),
           format.c_str(),
           "answer",
           42,
           0xDEADBEEFULL,
           'a');
  std::string expected(expected_buffer);

  std::string out = handler_proxy<AsyncAction::printf>(
      bpftrace, format, "answer", 42, 0xDEADBEEFULL, 'a');

  EXPECT_EQ(expected, out)
      << "printf_handler should format multiple arguments correctly";
}

TEST(async_action, print_non_map)
{
  struct TestCase {
    SizedType type;
    std::vector<uint8_t> content;
    std::string expected_output;
  };

  std::vector<TestCase> test_cases = {
    // Integer type test
    { .type = CreateInt64(),
      .content =
          []() {
            int64_t value = 123456789;
            std::vector<uint8_t> bytes(sizeof(value));
            for (size_t i = 0; i < sizeof(value); i++) {
              bytes[i] = reinterpret_cast<uint8_t *>(&value)[i];
            }
            return bytes;
          }(),
      .expected_output = "123456789\n" },
    // String type test
    { .type = CreateString(12),
      .content =
          []() {
            const char *value = "Hello world";
            std::vector<uint8_t> bytes(strlen(value) + 1);
            for (size_t i = 0; i < bytes.size(); i++) {
              bytes[i] = static_cast<uint8_t>(value[i]);
            }
            return bytes;
          }(),
      .expected_output = "Hello world\n" }
  };

  for (const auto &tc : test_cases) {
    CDefinitions no_c_defs;
    std::stringstream out;
    TextOutput output(no_c_defs, out);
    auto bpftrace = get_mock_bpftrace();

    bpftrace->resources.non_map_print_args.emplace_back(tc.type);
    size_t total_size = sizeof(AsyncEvent::PrintNonMap) + tc.content.size();
    char buffer[total_size];
    memset(buffer, 0, total_size);

    auto *print_event = reinterpret_cast<AsyncEvent::PrintNonMap *>(buffer);
    print_event->action_id = static_cast<uint64_t>(AsyncAction::print_non_map);
    print_event->print_id = 0;
    std::ranges::copy(tc.content, print_event->content);

    print_non_map_handler(*bpftrace, output, print_event);

    EXPECT_EQ(tc.expected_output, out.str())
        << "print_non_map_handler failed for type: " << tc.type.GetName();
  }
}

TEST(async_action, watchpoint_attach_out_of_bound)
{
  CDefinitions no_c_defs;
  std::stringstream out;
  TextOutput output(no_c_defs, out);
  auto mock_bpftrace = get_mock_bpftrace();
  BPFtrace &bpftrace = *mock_bpftrace;
  bpftrace.procmon_ = std::make_unique<MockProcMon>(1234);
  auto invalid_index = 10;
  AsyncEvent::Watchpoint watch_event(
      static_cast<int>(AsyncAction::watchpoint_attach), invalid_index, 0x1234);

  // Combine the `EXPECT_CALL` with the `EXPECT_DEATH`
  // FYI: https://github.com/google/googletest/issues/1004
  auto watchpoint_attach_handler_op = [&] {
    EXPECT_CALL(*mock_bpftrace, resume_tracee(testing::_)).Times(1);
    watchpoint_attach_handler(bpftrace, output, &watch_event);
  };

  EXPECT_DEATH(watchpoint_attach_handler_op(),
               "Invalid watchpoint probe idx=" + std::to_string(invalid_index));
}

TEST(async_action, watchpoint_attach_duplicated_address)
{
  CDefinitions no_c_defs;
  std::stringstream out;
  TextOutput output(no_c_defs, out);
  auto mock_bpftrace = get_mock_bpftrace();
  BPFtrace &bpftrace = *mock_bpftrace;
  bpftrace.procmon_ = std::make_unique<MockProcMon>(1234);
  AsyncEvent::Watchpoint watch_event(
      static_cast<int>(AsyncAction::watchpoint_attach), 0, 0x1234);
  Probe probe;
  probe.type = ProbeType::watchpoint;
  probe.address = 0x1234;
  bpftrace.resources.watchpoint_probes.push_back(std::move(probe));
  EXPECT_CALL(*mock_bpftrace, attach_probe(testing::_, testing::_)).Times(0);
  EXPECT_CALL(*mock_bpftrace, resume_tracee(testing::_)).Times(1);
  watchpoint_attach_handler(bpftrace, output, &watch_event);
}

TEST(async_action, watchpoint_attach_enospc_exception)
{
  CDefinitions no_c_defs;
  std::stringstream out;
  TextOutput output(no_c_defs, out);
  auto mock_bpftrace = get_mock_bpftrace();
  BPFtrace &bpftrace = *mock_bpftrace;
  bpftrace.procmon_ = std::make_unique<MockProcMon>(1234);
  AsyncEvent::Watchpoint watch_event(
      static_cast<int>(AsyncAction::watchpoint_attach), 0, 0x1234);
  Probe probe;
  probe.type = ProbeType::watchpoint;
  probe.address = 0x12345678;
  bpftrace.resources.watchpoint_probes.push_back(std::move(probe));
  const char *expected_substring = "Failed to attach watchpoint probe. You are "
                                   "out of watchpoint registers.";
  EXPECT_CALL(*mock_bpftrace, attach_probe(testing::_, testing::_))
      .WillOnce(
          testing::Throw(util::EnospcException("No more HW registers left")));
  EXPECT_CALL(*mock_bpftrace, resume_tracee(testing::_)).Times(1);
  watchpoint_attach_handler(bpftrace, output, &watch_event);
  EXPECT_THAT(out.str(), testing::HasSubstr(expected_substring))
      << "Watchpoint_attach output should contain the result of \""
      << expected_substring << "\"";
}

TEST(async_action, watchpoint_attach_empty_probes)
{
  CDefinitions no_c_defs;
  std::stringstream out;
  TextOutput output(no_c_defs, out);
  auto mock_bpftrace = get_mock_bpftrace();
  BPFtrace &bpftrace = *mock_bpftrace;
  bpftrace.procmon_ = std::make_unique<MockProcMon>(1234);
  AsyncEvent::Watchpoint watch_event(
      static_cast<int>(AsyncAction::watchpoint_attach), 0, 0x1234);
  Probe probe;
  probe.type = ProbeType::watchpoint;
  probe.address = 0x12345678;
  bpftrace.resources.watchpoint_probes.push_back(std::move(probe));
  EXPECT_CALL(*mock_bpftrace, attach_probe(testing::_, testing::_))
      .WillOnce(testing::Return(std::vector<std::unique_ptr<AttachedProbe>>{}));
  EXPECT_THROW(watchpoint_attach_handler(bpftrace, output, &watch_event),
               util::FatalUserException);
}

TEST(async_action, watchpoint_attach_resume_tracee_failed)
{
  CDefinitions no_c_defs;
  std::stringstream out;
  TextOutput output(no_c_defs, out);
  auto mock_bpftrace = get_mock_bpftrace();
  BPFtrace &bpftrace = *mock_bpftrace;
  bpftrace.procmon_ = std::make_unique<MockProcMon>(1234);
  AsyncEvent::Watchpoint watch_event(
      static_cast<int>(AsyncAction::watchpoint_attach), 0, 0x1234);
  Probe probe;
  probe.type = ProbeType::watchpoint;
  probe.address = 0x1234;
  bpftrace.resources.watchpoint_probes.push_back(std::move(probe));
  EXPECT_CALL(*mock_bpftrace, attach_probe(testing::_, testing::_)).Times(0);
  EXPECT_CALL(*mock_bpftrace, resume_tracee(testing::_))
      .WillOnce(testing::Return(-1));
  EXPECT_THROW(watchpoint_attach_handler(bpftrace, output, &watch_event),
               util::FatalUserException);
}

TEST(async_action, asyncwatchpoint_attach_ignore_duplicated_addr)
{
  CDefinitions no_c_defs;
  std::stringstream out;
  TextOutput output(no_c_defs, out);
  auto mock_bpftrace = get_mock_bpftrace();
  BPFtrace &bpftrace = *mock_bpftrace;
  bpftrace.procmon_ = std::make_unique<MockProcMon>(1234);
  AsyncEvent::Watchpoint watch_event(
      static_cast<int>(AsyncAction::watchpoint_attach), 0, 0x1234);
  Probe probe;
  probe.type = ProbeType::watchpoint;
  probe.address = 0x1234;
  probe.async = true;
  bpftrace.resources.watchpoint_probes.push_back(std::move(probe));
  EXPECT_CALL(*mock_bpftrace, attach_probe(testing::_, testing::_)).Times(0);
  EXPECT_CALL(*mock_bpftrace, resume_tracee(testing::_)).Times(0);
  watchpoint_attach_handler(bpftrace, output, &watch_event);
}
} // namespace bpftrace::test::async_action
