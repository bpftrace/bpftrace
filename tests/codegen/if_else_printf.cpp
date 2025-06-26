#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, if_else_printf)
{
  test("kprobe:f { if (pid > 10) { printf(\"hi\\n\"); } else "
       "{printf(\"hello\\n\")} }",

       NAME);
}

} // namespace bpftrace::test::codegen
