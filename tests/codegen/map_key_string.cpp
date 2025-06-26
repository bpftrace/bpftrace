#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, map_key_string)
{
  test(R"(kprobe:f { @x["a", "b"] = 44 })",

       NAME);
}

} // namespace bpftrace::test::codegen
