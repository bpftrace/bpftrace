#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

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

} // namespace codegen
} // namespace test
} // namespace bpftrace
