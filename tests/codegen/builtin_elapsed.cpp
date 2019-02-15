#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, builtin_elapsed)
{
  /*
   * TODO: add test. The problem that needs fixing first is that the codegen
   * includes this line:
   *
   * %1 = add i64 %get_ns, -956821864668979
   *
   * That's the bpftrace epoch time, hardcoded in BPF. Which is what we want.
   * But it varies between runs of bpftrace, so this line will change every
   * time, causing the test to fail. We need a way to ignore this number
   * in the test.
   */
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
