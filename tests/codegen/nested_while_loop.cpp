#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

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

} // namespace codegen
} // namespace test
} // namespace bpftrace
