#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, nested_while_loop)
{
  test(R"PROG(
i:s:1 {
  $i=1;
  while ($i <= 100) {
    $j=0;
    $i++;
    while ($j <= 100 ) {
      @++;
      $j++;
    }
  }
}
)PROG",
       NAME);
}

} // namespace bpftrace::test::codegen
