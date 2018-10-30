#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, struct_save)
{
  auto expected = R"EXPECTED(; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"kprobe:f"(i8* nocapture readnone) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %"@foo_val" = alloca [12 x i8], align 1
  %"@foo_key" = alloca i64, align 8
  %1 = bitcast i64* %"@foo_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  store i64 0, i64* %"@foo_key", align 8
  %2 = getelementptr inbounds [12 x i8], [12 x i8]* %"@foo_val", i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %2)
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)([12 x i8]* nonnull %"@foo_val", i64 12, i64 0)
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo, i64* nonnull %"@foo_key", [12 x i8]* nonnull %"@foo_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %2)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
)EXPECTED";

  test("struct Foo { int x, y, z; }"
       "kprobe:f"
       "{"
       "  @foo = (Foo)0;"
       "}",
       expected);

  test("struct Foo { int x, y, z; }"
       "kprobe:f"
       "{"
       "  @foo = *(Foo*)0;"
       "}",
       expected);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
