#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_system)
{
  test(" kprobe:f { system(\"echo %d\", 100) }",

       NAME,
       false);
}

} // namespace bpftrace::test::codegen
