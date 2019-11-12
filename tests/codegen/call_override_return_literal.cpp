#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_override_return_literal)
{
  test(
      "kprobe:f { override_return(-1); }",

      R"EXPECTED(define i64 @"kprobe:f"(i8*) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %override_return = tail call i64 inttoptr (i64 58 to i64 (i8*, i64)*)(i8* %0, i64 -1)
  ret i64 0
}
)EXPECTED",
      false);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
