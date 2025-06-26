#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, map_key_struct)
{
  test("struct Foo { int x; }"
       "kprobe:f"
       "{"
       "  @x[*((struct Foo *)arg0)] = 44;"
       "}",

       NAME);
}

} // namespace bpftrace::test::codegen
