#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, ternary_buf)
{
  test(R"(kprobe:f { $x = nsecs ? buf("hi", 2) : buf("bye", 3); })", NAME);
}

} // namespace bpftrace::test::codegen
