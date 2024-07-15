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

TEST(codegen, for_map_variables_multiple_loops)
{
  test(R"(
    BEGIN
    {
      @[0] = 0;

      $var1 = 0;
      $var2 = 0;

      // Ensure we get unique ctx_t types for each loop
      for ($_ : @) {
        $var1++;
      }
      for ($_ : @) {
        $var1++;
        $var2++;
      }
    })",
       NAME);
}

} // namespace bpftrace::test::codegen
