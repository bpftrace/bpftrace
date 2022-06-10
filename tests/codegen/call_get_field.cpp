#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_get_field)
{
  test("struct Foo { char c; long l; } kprobe:f { $foo = (struct Foo*)arg0; "
       "if (has_field(struct Foo, \"c\")) {"
       "  $c = get_field(*$foo, \"c\");"
       "}"
       "}",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
