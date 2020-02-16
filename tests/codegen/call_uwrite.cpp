#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_uwrite)
{
  test("kprobe:f { uwrite(10, 20, 6) }",

       R"EXPECTED(; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #0

define i64 @"kprobe:f"(i8* nocapture readnone) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %uwrite_src = alloca i64, align 8
  %1 = bitcast i64* %uwrite_src to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  store i64 20, i64* %uwrite_src, align 8
  %uwrite = call i64 inttoptr (i64 36 to i64 (i8*, i8*, i32)*)(i64 10, i64* nonnull %uwrite_src, i64 6)
  ret i64 0
}

attributes #0 = { argmemonly nounwind }
)EXPECTED",
       false);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
