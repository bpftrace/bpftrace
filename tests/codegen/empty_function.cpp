#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, empty_function)
{
  test("kprobe:f { 1; }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
