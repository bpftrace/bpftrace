#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, ternary_str)
{
  test(R"(kprobe:f { @x = pid < 10000 ? "lo" : "hi"; })", NAME);
}

} // namespace bpftrace::test::codegen
