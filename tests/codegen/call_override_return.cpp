#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_override_return)
{
  test(
      "kprobe:f { override_return(arg0); }",

      R"EXPECTED(define i64 @"kprobe:f"(i8*) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %1 = getelementptr i8, i8* %0, i64 112
  %arg0 = load i64, i8* %1, align 8
  %override_return = tail call i64 inttoptr (i64 58 to i64 (i8*, i64)*)(i8* %0, i64 %arg0)
  ret i64 0
}
)EXPECTED",
      false);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
