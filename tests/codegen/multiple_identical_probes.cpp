#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, multiple_identical_probes)
{
  test("kprobe:f { 1; } kprobe:f { 1; }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
