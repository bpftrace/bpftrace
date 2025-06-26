#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_time)
{
  test("kprobe:f { time(); }",

       NAME);
}

} // namespace bpftrace::test::codegen
