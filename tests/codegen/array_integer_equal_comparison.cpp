#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, array_integer_equal_comparison)
{
  auto bpftrace = get_mock_bpftrace();
  if (bpftrace->has_loop())
  {
    return;
  }

  test("struct Foo { int arr[4]; }"
       "kprobe:f"
       "{"
       "  $a = ((struct Foo *)arg0)->arr;"
       "  $b = ((struct Foo *)arg0)->arr;"
       "  if ($a == $b)"
       "  {"
       "    exit();"
       "  }"
       "}",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
