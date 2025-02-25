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

TEST(codegen, map_value_int_scratch_buf)
{
  test_stack_or_scratch_buffer("kprobe:f { @x = 1; @y = @x }",
                               NAME,
                               SMALL_ON_STACK_LIMIT);
}

TEST(codegen, map_value_int_stack)
{
  test_stack_or_scratch_buffer("kprobe:f { @x = 1; @y = @x }",
                               NAME,
                               LARGE_ON_STACK_LIMIT);
}

// Using two tuples with different sizes will trigger copying tuples to the
// scratch buffer or stack prior to updating the map
TEST(codegen, map_value_tuple_scratch_buf)
{
  test_stack_or_scratch_buffer(
      "kprobe:f { @x = (\"xxx\", 1); @x = (\"xxxxxxx\", 1); @y = @x }",
      NAME,
      SMALL_ON_STACK_LIMIT);
}

TEST(codegen, map_value_tuple_stack)
{
  test_stack_or_scratch_buffer(
      "kprobe:f { @x = (\"xxx\", 1); @x = (\"xxxxxxx\", 1); @y = @x }",
      NAME,
      LARGE_ON_STACK_LIMIT);
}

// Use an if statement with same variable name with two scopes to ensure
// initialization happens prior to both scopes
TEST(codegen, variable_scratch_buf)
{
  test_stack_or_scratch_buffer(
      "kprobe:f { if (arg0 > 0) { $x = 1; } else { $x = 2 } }",
      NAME,
      SMALL_ON_STACK_LIMIT);
}

TEST(codegen, variable_stack)
{
  test_stack_or_scratch_buffer(
      "kprobe:f { if (arg0 > 0) { $x = 1; } else { $x = 2 } }",
      NAME,
      LARGE_ON_STACK_LIMIT);
}

TEST(codegen, map_key_scratch_buf)
{
  test_stack_or_scratch_buffer("kprobe:f { @x[1] = 1; @y[\"yyyy\"] = @x[1]; }",
                               NAME,
                               SMALL_ON_STACK_LIMIT);
}

TEST(codegen, map_key_stack)
{
  test_stack_or_scratch_buffer("kprobe:f { @x[1] = 1; @y[\"yyyy\"] = @x[1]; }",
                               NAME,
                               LARGE_ON_STACK_LIMIT);
}

// Test map keys with aggregation and map-related functions
TEST(codegen, call_map_key_scratch_buf)
{
  test_stack_or_scratch_buffer("kprobe:f { @x[1] = count(); @y = hist(10); "
                               "has_key(@x, 1); delete(@x, 1); }",
                               NAME,
                               SMALL_ON_STACK_LIMIT);
}

TEST(codegen, call_map_key_stack)
{
  test_stack_or_scratch_buffer("kprobe:f { @x[1] = count(); @y = hist(10); "
                               "has_key(@x, 1); delete(@x, 1); }",
                               NAME,
                               LARGE_ON_STACK_LIMIT);
}

TEST(codegen, probe_str_scratch_buf)
{
  test_stack_or_scratch_buffer("tracepoint:sched:sched_one { @x = probe }",
                               NAME,
                               SMALL_ON_STACK_LIMIT);
}

TEST(codegen, probe_str_stack)
{
  test_stack_or_scratch_buffer("tracepoint:sched:sched_one { @x = probe }",
                               NAME,
                               LARGE_ON_STACK_LIMIT);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
