#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, struct_bool)
{
  test("struct Foo { int x; bool b; }"
       "kprobe:f"
       "{"
       "  $foo = *(struct Foo*)arg0;"
       "  @b = $foo.b;"
       "}",
       std::string(NAME) + "_1");

  test("struct Foo { int x; bool b; }"
       "kprobe:f"
       "{"
       "  $foo = (struct Foo*)arg0;"
       "  @b = $foo->b;"
       "}",
       std::string(NAME) + "_2");
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
