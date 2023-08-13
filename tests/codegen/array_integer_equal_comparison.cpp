#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

namespace {
constexpr auto PROG = "struct Foo { int arr[4]; }"
                      "kprobe:f"
                      "{"
                      "  $a = ((struct Foo *)arg0)->arr;"
                      "  $b = ((struct Foo *)arg0)->arr;"
                      "  if ($a == $b)"
                      "  {"
                      "    exit();"
                      "  }"
                      "}";
}

TEST(codegen, array_integer_equal_comparison)
{
  auto bpftrace = get_mock_bpftrace();

  // Force unroll fallback
  auto feature = std::make_unique<MockBPFfeature>(true);
  feature->has_loop(false);
  bpftrace->feature_ = std::move(feature);

  test(*bpftrace, PROG, NAME);
}

TEST(codegen, array_integer_equal_comparison_no_unroll)
{
  auto bpftrace = get_mock_bpftrace();

  // Force loop generation
  auto feature = std::make_unique<MockBPFfeature>(true);
  feature->has_loop(true);
  bpftrace->feature_ = std::move(feature);

  test(*bpftrace, PROG, NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
