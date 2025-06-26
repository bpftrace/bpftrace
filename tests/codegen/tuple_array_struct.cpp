#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, tuple_array_struct)
{
  test("struct Foo { char c; int x; } struct Bar { int y[4]; }"
       "kprobe:f"
       "{"
       "  @t = (*((struct Foo *)arg0), ((struct Bar *)arg1)->y);"
       "}",

       NAME);
}

} // namespace bpftrace::test::codegen
