#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, struct_save_nested)
{
  test("struct Foo { int m; struct { int x; int y; } bar; int n; }"
       "kprobe:f"
       "{"
       "  @foo = *(struct Foo*)arg0;"
       "  @bar = @foo.bar;"
       "  @x = @foo.bar.x;"
       "}",
       NAME);
}

} // namespace bpftrace::test::codegen
