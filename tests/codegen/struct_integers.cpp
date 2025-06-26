#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, struct_integers)
{
  test("struct Foo { int x; }"
       "kprobe:f"
       "{"
       "  $foo = *(struct Foo*)arg0;"
       "  @x = $foo.x;"
       "}",
       std::string(NAME) + "_1");

  test("struct Foo { int x; }"
       "kprobe:f"
       "{"
       "  $foo = (struct Foo*)arg0;"
       "  @x = $foo->x;"
       "}",
       std::string(NAME) + "_2");
}

} // namespace bpftrace::test::codegen
