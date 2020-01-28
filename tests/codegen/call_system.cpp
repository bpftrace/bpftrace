#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_system)
{
  test(" kprobe:f { system(\"echo %d\", 100) }",

       NAME,
       false);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
