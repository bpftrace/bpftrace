#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, struct_integer_ptr)
{
  test("struct Foo { int *x; }"
       "kprobe:f"
       "{"
       "  $foo = *(struct Foo*)arg0;"
       "  @x = *$foo.x;"
       "}",
       std::string(NAME) + "_1");

  test("struct Foo { int *x; }"
       "kprobe:f"
       "{"
       "  $foo = (struct Foo*)arg0;"
       "  @x = *$foo->x;"
       "}",
       std::string(NAME) + "_2");
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
