#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_signal)
{
  test("k:f { signal(arg0); }",
R"EXPECTED(define i64 @"kprobe:f"(i8* nocapture readonly) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %1 = getelementptr i8, i8* %0, i64 112
  %arg0 = load i64, i8* %1, align 8
  %2 = trunc i64 %arg0 to i32
  %signal = tail call i64 inttoptr (i64 109 to i64 (i32)*)(i32 %2)
  ret i64 0
}
)EXPECTED", false);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
