#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, tuple_array_struct)
{
  test("struct Foo { char c; int x; } struct Bar { int y[4]; }"
       "kprobe:f"
       "{"
       "  @t = (*((struct Foo *)arg0), ((struct Bar *)arg1)->y);"
       "}",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
