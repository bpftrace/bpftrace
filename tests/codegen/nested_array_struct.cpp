#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, nested_array_struct)
{
  test("struct Bar { int x; } struct Foo { struct Bar bar[2][2]; }"
       "kprobe:f"
       "{"
       "  @bar[42] = ((struct Foo *)arg0)->bar;"
       "  @ = @bar[42][0][1].x;"
       "}",

       NAME);
}

} // namespace bpftrace::test::codegen
