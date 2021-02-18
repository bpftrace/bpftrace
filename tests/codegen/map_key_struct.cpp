#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, map_key_struct)
{
  test("struct Foo { int x; }"
       "kprobe:f"
       "{"
       "  @x[*((struct Foo *)arg0)] = 44;"
       "}",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
