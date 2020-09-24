#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, struct_nested_struct_anon)
{
  test("struct Foo { struct { int x; } bar; }"
       "kprobe:f"
       "{"
       "  $foo = *(struct Foo*)arg0;"
       "  @x = $foo.bar.x;"
       "}",
       std::string(NAME) + "_1");

  test("struct Foo { struct { int x; } bar; }"
       "kprobe:f"
       "{"
       "  $foo = (struct Foo*)arg0;"
       "  @x = $foo->bar.x;"
       "}",
       std::string(NAME) + "_2");
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
