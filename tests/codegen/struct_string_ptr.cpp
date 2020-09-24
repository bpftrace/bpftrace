#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, struct_string_ptr)
{
  test("struct Foo { char *str; }"
       "kprobe:f"
       "{"
       "  $foo = (struct Foo*)arg0;"
       "  @mystr = str($foo->str);"
       "}",
       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
