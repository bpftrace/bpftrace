#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, struct_save_string)
{
  test("struct Foo { char str[32]; }"
       "kprobe:f"
       "{"
       "  @foo = *(struct Foo*)arg0;"
       "  @str = @foo.str;"
       "}",
       NAME);
}

} // namespace bpftrace::test::codegen
