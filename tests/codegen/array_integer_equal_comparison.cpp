#include "common.h"

namespace bpftrace::test::codegen::array_integer_equal_comparison {
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

TEST(codegen, array_integer_equal_comparison)
{
  test(PROG, NAME);
}

} // namespace bpftrace::test::codegen::array_integer_equal_comparison
