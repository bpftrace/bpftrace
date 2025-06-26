#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, map_key_array)
{
  test("struct Foo { int arr[4]; }"
       "kprobe:f"
       "{"
       "  @x[((struct Foo *)arg0)->arr] = 44;"
       "}",

       NAME);
}

} // namespace bpftrace::test::codegen
