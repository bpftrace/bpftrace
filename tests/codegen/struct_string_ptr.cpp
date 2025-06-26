#include "common.h"

namespace bpftrace::test::codegen {

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

} // namespace bpftrace::test::codegen
