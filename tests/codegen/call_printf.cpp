#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_printf)
{
  test("struct Foo { char c; long l; } kprobe:f { $foo = (struct Foo*)arg0; "
       "printf(\"%c %lu\\n\", $foo->c, $foo->l) }",

       NAME);
}

} // namespace bpftrace::test::codegen
