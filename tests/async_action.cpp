#include <regex>

#include "ast/async_event_types.h"
#include "ast/location.h"
#include "async_action.h"
#include "attached_probe.h"
#include "bpftrace.h"
#include "mocks.h"
#include "output/text.h"
#include "types.h"
#include "util/exceptions.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace bpftrace::test::async_action {

using namespace bpftrace::async_action;

// Used for resolving all C definitions.
static ast::CDefinitions no_c_defs;

class AsyncActionTest : public testing::Test {
public:
  AsyncActionTest()
      : bpftrace(get_mock_bpftrace()),
        output(out, out),
        handlers(*bpftrace, no_c_defs, output) {};

  std::unique_ptr<MockBPFtrace> bpftrace;
  std::stringstream out;
  output::TextOutput output;
  AsyncHandlers handlers;
};

// Process string type argument - handle const char*
template <typename T, typename... R>
void build_each_field(std::vector<Field> &fields,
                      ssize_t offset,
                      T arg,
                      R... rest)
{
  SizedType ty;
  // We only pack string and integer values.
  if constexpr (std::is_same_v<T, std::string>) {
    ty = CreateString(arg.size() + 1);
  } else if constexpr (std::is_integral_v<T>) {
    ty = CreateInt(sizeof(T) * 8);
  } else {
    static_assert(sizeof(T) == 0, "unknown field type");
  }
  fields.push_back(Field{
      .name = "arg", .type = ty, .offset = offset, .bitfield = std::nullopt });
  if constexpr (sizeof...(R) != 0) {
    build_each_field(fields, offset + ty.GetSize(), rest...);
  }
}

template <typename... Ts>
std::vector<Field> build_fields(Ts... args)
{
  std::vector<Field> fields;
  if constexpr (sizeof...(Ts) != 0) {
    build_each_field(fields, 0, args...);
  }
  return fields;
}

template <AsyncAction id, typename... Args>
Result<std::string> handler_proxy(AsyncActionTest &test,
                                  std::string &fmt_str,
                                  [[maybe_unused]] Args... args)
{
  FormatString fmt(fmt_str);

  auto fields = build_fields(args...);
  auto arg_data = OpaqueValue::from(static_cast<uint64_t>(id));
  arg_data = (arg_data + ... + OpaqueValue::from<Args>(args));

  static_assert((id == AsyncAction::syscall || id == AsyncAction::cat ||
                 id == AsyncAction::printf) &&
                "Only support syscall, cat, and printf");
  if (id == AsyncAction::syscall) {
    test.bpftrace->resources.system_args.emplace_back(fmt, fields);
    auto ok = test.handlers.syscall(arg_data);
    if (!ok) {
      return ok.takeError();
    }
  } else if (id == AsyncAction::cat) {
    test.bpftrace->resources.cat_args.emplace_back(fmt, fields);
    auto ok = test.handlers.cat(arg_data);
    if (!ok) {
      return ok.takeError();
    }
  } else if (id == AsyncAction::printf) {
    test.bpftrace->resources.printf_args.emplace_back(
        fmt, fields, PrintfSeverity::NONE, SourceInfo());
    auto ok = test.handlers.printf(arg_data);
    if (!ok) {
      return ok.takeError();
    }
  }

  auto s = test.out.str();
  test.out.str("");
  return s;
}

TEST_F(AsyncActionTest, join)
{
  bpftrace->resources.join_args.emplace_back(",");

  auto join = AsyncEvent::Join{
    .action_id = static_cast<uint64_t>(AsyncAction::join),
    .join_id = 0,
    .content = {},
  };
  auto arg = OpaqueValue::from(join) +
             OpaqueValue::string("/bin/ls", bpftrace->join_argsize_) +
             OpaqueValue::string("-la", bpftrace->join_argsize_) +
             OpaqueValue::string("/tmp", bpftrace->join_argsize_);

  ASSERT_TRUE(bool(handlers.join(arg)));
  EXPECT_EQ("/bin/ls,-la,/tmp\n", out.str());
}

TEST_F(AsyncActionTest, time)
{
  bpftrace->resources.time_args.emplace_back("%Y-%m-%d");
  bpftrace->resources.time_args.emplace_back("%H:%M:%S");
  bpftrace->resources.time_args.emplace_back("%a, %d %b %Y");

  // The first format
  {
    AsyncEvent::Time time_event(static_cast<int>(AsyncAction::time), 0);
    ASSERT_TRUE(bool(handlers.time(OpaqueValue::from(time_event))));

    std::regex pattern(R"(\d{4}-\d{2}-\d{2})");
    EXPECT_TRUE(std::regex_match(out.str(), pattern));
    out.str("");
  }

  // The second format
  {
    AsyncEvent::Time time_event(static_cast<int>(AsyncAction::time), 1);
    ASSERT_TRUE(bool(handlers.time(OpaqueValue::from(time_event))));

    std::regex pattern(R"(\d{2}:\d{2}:\d{2})");
    EXPECT_TRUE(std::regex_match(out.str(), pattern));
    out.str("");
  }

  // The third format
  {
    AsyncEvent::Time time_event(static_cast<int>(AsyncAction::time), 2);
    ASSERT_TRUE(bool(handlers.time(OpaqueValue::from(time_event))));

    std::regex pattern(R"([A-Za-z]+, \d{2} [A-Za-z]+ \d{4})");
    EXPECT_TRUE(std::regex_match(out.str(), pattern));
  }
}

TEST_F(AsyncActionTest, time_invalid_format)
{
  // invalid time format string
  std::string very_long_format(
      bpftrace::async_action::AsyncHandlers::MAX_TIME_STR_LEN, 'X');
  very_long_format = "%Y-%m-%d " + very_long_format;
  bpftrace->resources.time_args.emplace_back(very_long_format);
  AsyncEvent::Time time_event(static_cast<int>(AsyncAction::time), 0);

  testing::internal::CaptureStderr();

  auto out = handlers.time(OpaqueValue::from(time_event));
  ASSERT_FALSE(bool(out));
  EXPECT_THAT(llvm::toString(out.takeError()),
              testing::HasSubstr("strftime returned"));
}

TEST_F(AsyncActionTest, runtime_error)
{
  struct TestCase {
    RuntimeErrorId rte_id;
    bpf_func_id func_id;
    int return_value;
    std::string expected_substring;
    std::string filename;
    int line;
    int column;
  };

  std::vector<TestCase> test_cases = {
    // case 1: `map_update_elem` returns `-E2BIG`
    { .rte_id = RuntimeErrorId::HELPER_ERROR,
      .func_id = BPF_FUNC_map_update_elem,
      .return_value = -E2BIG,
      .expected_substring = "WARNING: Map full; can't update element",
      .filename = std::string("test1.bt"),
      .line = 10,
      .column = 5 },
    // case 2: `map_delete_elem` returns `-ENOENT`
    { .rte_id = RuntimeErrorId::HELPER_ERROR,
      .func_id = BPF_FUNC_map_delete_elem,
      .return_value = -ENOENT,
      .expected_substring =
          "WARNING: Can't delete map element because it does not exist",
      .filename = std::string("test2.bt"),
      .line = 15,
      .column = 8 },
    // case 3: `map_lookup_elem` failed to lookup map element
    { .rte_id = RuntimeErrorId::HELPER_ERROR,
      .func_id = BPF_FUNC_map_lookup_elem,
      .return_value = 0,
      .expected_substring =
          "WARNING: Can't lookup map element because it does not exist",
      .filename = std::string("test3.bt"),
      .line = 20,
      .column = 3 },
    // case 4: default case - other function ID and error code
    { .rte_id = RuntimeErrorId::HELPER_ERROR,
      .func_id = BPF_FUNC_trace_printk,
      .return_value = -EPERM,
      .expected_substring = "WARNING: " + std::string(strerror(EPERM)),
      .filename = std::string("test4.bt"),
      .line = 25,
      .column = 1 },
    // case 5: divide by zero error
    { .rte_id = RuntimeErrorId::DIVIDE_BY_ZERO,
      .func_id = BPF_FUNC_trace_printk, // unused
      .return_value = 0,                // unused
      .expected_substring =
          "WARNING: Divide or modulo by 0 detected. This can lead to "
          "unexpected results. 1 is being used as the result.",
      .filename = std::string("test4.bt"),
      .line = 25,
      .column = 1 }
  };

  uint64_t async_id = 1;
  for (const auto &tc : test_cases) {
    ast::SourceLocation src_loc;
    src_loc.begin = { .line = tc.line, .column = tc.column };
    src_loc.end = { .line = tc.line, .column = tc.column };
    auto location_chain = std::make_shared<ast::LocationChain>(src_loc);
    RuntimeErrorInfo info(tc.rte_id, tc.func_id, location_chain);

    bpftrace->resources.runtime_error_info.emplace(async_id, std::move(info));

    AsyncEvent::RuntimeError error_event(static_cast<int64_t>(
                                             AsyncAction::runtime_error),
                                         async_id,
                                         tc.return_value);

    ASSERT_TRUE(bool(handlers.runtime_error(OpaqueValue::from(error_event))));

    auto s = out.str();

    EXPECT_THAT(s, testing::HasSubstr(tc.expected_substring))
        << "warning substring doesn't have string";

    std::string expected_loc = std::to_string(tc.line) + ":" +
                               std::to_string(tc.column);
    EXPECT_THAT(s, testing::HasSubstr(expected_loc))
        << "Source location not found in output: " << expected_loc;

    EXPECT_THAT(s, testing::HasSubstr(std::to_string(tc.return_value)))
        << "Return value not found in output: " << tc.return_value;
    ++async_id;
  }
}

TEST_F(AsyncActionTest, syscall)
{
  struct TestCase {
    std::string cmd;
    std::optional<std::string> args;
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

  bpftrace->safe_mode_ = false;
  for (auto &tc : test_cases) {
    auto out = [&]() {
      if (tc.args.has_value()) {
        return handler_proxy<AsyncAction::syscall>(*this,
                                                   tc.cmd,
                                                   tc.args.value());
      } else {
        return handler_proxy<AsyncAction::syscall>(*this, tc.cmd);
      }
    }();

    ASSERT_TRUE(bool(out));
    EXPECT_THAT(*out, testing::HasSubstr(tc.expected_substring))
        << "Syscall output should contain the result of 'echo test'";
  }
}

TEST_F(AsyncActionTest, syscall_safe_mode)
{
  auto cmd = std::string("echo test");

  auto out = handler_proxy<AsyncAction::syscall>(*this, cmd);
  ASSERT_FALSE(bool(out))
      << "Expected syscall_handler to return an error in safe mode";
  EXPECT_THAT(llvm::toString(out.takeError()),
              testing::HasSubstr(
                  "syscall() not allowed in safe mode. Use '--unsafe'."))
      << "Error should indicate syscall is not allowed in safe mode";
}

TEST_F(AsyncActionTest, cat)
{
  std::string test_content = "Hello, cat_handler test!\nThis is line 2.\n";
  char filename[] = "/tmp/bpftrace-test-cat-XXXXXX";
  int fd = mkstemp(filename);
  ASSERT_NE(fd, -1) << "Failed to create temporary file";
  ASSERT_EQ(write(fd, test_content.c_str(), test_content.length()),
            static_cast<ssize_t>(test_content.length()));
  close(fd);

  bpftrace->config_->max_cat_bytes = 1024;
  auto cmd = std::string("%s/%s");
  std::string basename = std::string(filename).substr(5);
  auto out = handler_proxy<AsyncAction::cat>(
      *this, cmd, std::string("/tmp"), basename);
  ASSERT_TRUE(bool(out));

  EXPECT_EQ(test_content, *out)
      << "cat_handler should output the file content correctly";

  std::remove(filename);
}

TEST_F(AsyncActionTest, printf)
{
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

  auto out = handler_proxy<AsyncAction::printf>(*this,
                                                format,
                                                std::string("answer"),
                                                42ULL,
                                                0xDEADBEEFULL,
                                                static_cast<uint64_t>('a'));
  ASSERT_TRUE(bool(out));

  EXPECT_EQ(expected, *out)
      << "printf_handler should format multiple arguments correctly";
}

TEST_F(AsyncActionTest, print_non_map)
{
  struct TestCase {
    SizedType type;
    OpaqueValue content;
    std::string expected_output;
  };

  std::vector<TestCase> test_cases = {
    // Integer type test
    { .type = CreateInt64(),
      .content = OpaqueValue::from<int64_t>(123456789),
      .expected_output = "123456789\n" },
    // String type test
    { .type = CreateString(12),
      .content = OpaqueValue::string("Hello world", 12),
      .expected_output = "Hello world\n" }
  };

  for (const auto &tc : test_cases) {
    bpftrace->resources.non_map_print_args.clear();
    bpftrace->resources.non_map_print_args.emplace_back(tc.type);

    auto print_event = AsyncEvent::PrintNonMap{
      .action_id = static_cast<uint64_t>(AsyncAction::print_non_map),
      .print_id = 0,
      .content = {},
    };
    ASSERT_TRUE(bool(
        handlers.print_non_map(OpaqueValue::from(print_event) + tc.content)));

    EXPECT_EQ(tc.expected_output, out.str());
    out.str("");
  }
}

} // namespace bpftrace::test::async_action
