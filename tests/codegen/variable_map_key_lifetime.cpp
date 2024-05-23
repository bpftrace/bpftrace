#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, variable_map_key_lifetime)
{
  test(R"(BEGIN { $myvar = "abc"; @x[$myvar] = 1; @x[$myvar] = 1; })", NAME);
}

} // namespace bpftrace::test::codegen
