#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, for_map_strings)
{
  test(R"(begin { @map["abc"] = "xyz"; for ($kv : @map) { @x = $kv; } })",
       NAME);
}

} // namespace bpftrace::test::codegen
