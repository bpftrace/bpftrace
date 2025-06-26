#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, ternary_tuple)
{
  test(R"(kprobe:f { $x = nsecs ? ("hi", 1) : ("extralongstring", 2) })", NAME);
}

} // namespace bpftrace::test::codegen
