#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, variable_assign_array)
{
  test("struct Foo { int arr[4]; }"
       "kprobe:f"
       "{"
       "  $var = ((struct Foo *)arg0)->arr;"
       "  @x = $var[0]; "
       "}",

       NAME);
}

} // namespace bpftrace::test::codegen
