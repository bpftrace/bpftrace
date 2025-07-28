#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_print_error)
{
  test("struct Foo { char c; long l; } kprobe:f { $foo = (struct Foo*)arg0; "
       "print_error(\"%c %lu\\n\", $foo->c, $foo->l) }",

       NAME);
}

} // namespace bpftrace::test::codegen
