#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_cat)
{
  test("kprobe:f { cat(\"/proc/loadavg\"); }",

       NAME);
}

} // namespace bpftrace::test::codegen
