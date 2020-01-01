#include "common.h"

namespace bpftrace
{
namespace test
{
namespace codegen
{

TEST(codegen, call_fdpath)
{
  test("k:f { $path = fdpath(arg0); }",
       R"EXPECTED(; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #0

define i64 @"kprobe:f"(i8* nocapture readonly) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %str = alloca [64 x i8], align 1
  %1 = getelementptr inbounds [64 x i8], [64 x i8]* %str, i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %2 = getelementptr i8, i8* %0, i64 112
  %arg0 = load i64, i8* %2, align 8
  %fdpath = call i64 inttoptr (i64 116 to i64 (i8*, i32, i32)*)([64 x i8]* nonnull %str, i64 64, i64 %arg0)
  ret i64 0
}

attributes #0 = { argmemonly nounwind }
)EXPECTED",
       false);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
