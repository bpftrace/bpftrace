#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, preserve_static_offsets)
{
  // Standard optimization passes may or may not fold the args field into a
  // value that is no longer is dereferenced by static offset. The
  // `preserve_static_offset` instrinsic should be inserted always in order to
  // ensure that code generated is always compliant. This test uses a pattern
  // that will often result in saving the (illegal) intermediate value, to
  // ensure that the offset is preserved.
  test(R"PROG(
BEGIN {
  @test[1] = (uint64)1;
}
t:btf:tag
{
  if (strcontains(comm, "test")) {
    @test[(uint64)args.parent] = 1;
  }
  if (args.parent == @test[1]) {
    print((1));
  }
  if (args.parent == @test[1]) {
    print((1));
  }
}
)PROG",
       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
