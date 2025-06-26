#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, if_nested_printf)
{
  test("kprobe:f { if (pid > 10000) { if (pid % 2 == 0) { printf(\"hi\\n\");} "
       "} }",

       NAME);
}

} // namespace bpftrace::test::codegen
