#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

static constexpr uint64_t SMALL_ON_STACK_LIMIT = 0;
static constexpr uint64_t LARGE_ON_STACK_LIMIT = 128;
static constexpr uint64_t MAX_STRLEN = 64;

static void test_stack_or_scratch_buffer(const std::string &input,
                                         const std::string &name,
                                         uint64_t on_stack_limit)
{
  auto bpftrace = get_mock_bpftrace();
  bpftrace->feature_ = std::make_unique<MockBPFfeature>(true);
  auto configs = ConfigSetter(bpftrace->config_, ConfigSource::script);
  configs.set(ConfigKeyInt::on_stack_limit, on_stack_limit);
  configs.set(ConfigKeyInt::max_strlen, MAX_STRLEN);

  bpftrace->safe_mode_ = true;

  test(*bpftrace, input, name);
}

TEST(codegen, tuple_scratch_buf)
{
  test_stack_or_scratch_buffer("kprobe:f { (1, \"xxxx\") }",
                               NAME,
                               SMALL_ON_STACK_LIMIT);
}

TEST(codegen, tuple_stack)
{
  test_stack_or_scratch_buffer("kprobe:f { (1, \"xxxx\") }",
                               NAME,
                               LARGE_ON_STACK_LIMIT);
}

TEST(codegen, fmt_str_args_scratch_buf)
{
  test_stack_or_scratch_buffer("kprobe:f { printf(\"%s %d\\n\", \"xxxx\", 1) }",
                               NAME,
                               SMALL_ON_STACK_LIMIT);
}

TEST(codegen, fmt_str_args_stack)
{
  test_stack_or_scratch_buffer("kprobe:f { printf(\"%s %d\\n\", \"xxxx\", 1) }",
                               NAME,
                               LARGE_ON_STACK_LIMIT);
}

TEST(codegen, str_scratch_buf)
{
  test_stack_or_scratch_buffer("kprobe:f { str(arg0) }",
                               NAME,
                               SMALL_ON_STACK_LIMIT);
}

TEST(codegen, str_stack)
{
  test_stack_or_scratch_buffer("kprobe:f { str(arg0) }",
                               NAME,
                               LARGE_ON_STACK_LIMIT);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
