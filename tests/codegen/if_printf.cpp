#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, if_printf)
{
  test(R"(kprobe:f { if (pid > 10000) { printf("%d is high\n", pid); } })",

       NAME);
}

} // namespace bpftrace::test::codegen
