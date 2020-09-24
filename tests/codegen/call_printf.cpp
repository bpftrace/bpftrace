#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_printf)
{
  test("struct Foo { char c; long l; } kprobe:f { $foo = (struct Foo*)arg0; "
       "printf(\"%c %lu\\n\", $foo->c, $foo->l) }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
