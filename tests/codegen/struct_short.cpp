#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, struct_short)
{
  test("struct Foo { short x; }"
       "kprobe:f"
       "{"
       "  $foo = (struct Foo)0;"
       "  @x = $foo.x;"
       "}",
       std::string(NAME) + "_1");

  test("struct Foo { short x; }"
       "kprobe:f"
       "{"
       "  $foo = (struct Foo*)0;"
       "  @x = $foo->x;"
       "}",
       std::string(NAME) + "_2");
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
