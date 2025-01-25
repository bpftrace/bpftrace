#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, late_variable_decl)
{
  // This test is to ensure that late variable declarations in an outer scope
  // don't bleed into inner scopes earlier in the script.
  // All the $x variables below should get their own allocation
  test(R"(
    BEGIN
    {
      if (1) {
				$x = 1;
			}

			unroll(1) {
				$x = 2;
			}

			$i = 1;
      while($i) {
        --$i;
        $x = 3;
      }

			@map[16] = 32;
      for ($kv : @map) {
        $x = 4;
      }

      let $x = 5;
    })",
       NAME);
}

} // namespace bpftrace::test::codegen
