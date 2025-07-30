#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_errorf)
{
  test("struct Foo { char c; long l; } kprobe:f { $foo = (struct Foo*)arg0; "
       "errorf(\"%c %lu\\n\", $foo->c, $foo->l) }",

       NAME);
}

} // namespace bpftrace::test::codegen
