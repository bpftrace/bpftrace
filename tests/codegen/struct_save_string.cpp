#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

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

} // namespace codegen
} // namespace test
} // namespace bpftrace
