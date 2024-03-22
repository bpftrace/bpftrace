#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, for_map_variables)
{
  test(R"(
    BEGIN
    {
      @map[16] = 32;
      $var1 = 123;
      $var2 = "abc";
      $var3 = "def";
      for ($kv : @map) {
        $var1++;
        print($var3);
      }
      @len = $var1;
    })",
       NAME);
}

} // namespace bpftrace::test::codegen
