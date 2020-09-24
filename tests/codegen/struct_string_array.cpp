#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, struct_string_array)
{
  test("struct Foo { char str[32]; }"
       "kprobe:f"
       "{"
       "  $foo = *(struct Foo*)arg0;"
       "  @mystr = $foo.str;"
       "}",
       std::string(NAME) + "_1");

  test("struct Foo { char str[32]; }"
       "kprobe:f"
       "{"
       "  $foo = (struct Foo*)arg0;"
       "  @mystr = $foo->str;"
       "}",
       std::string(NAME) + "_2");
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
