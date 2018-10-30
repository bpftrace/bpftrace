#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, struct_short)
{
  auto expected = R"EXPECTED(; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"kprobe:f"(i8* nocapture readnone) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %"@x_val" = alloca i64, align 8
  %"@x_key" = alloca i64, align 8
  %Foo.x = alloca i16, align 2
  %"$foo" = alloca i16, align 8
  %tmpcast = bitcast i16* %"$foo" to [2 x i8]*
  %1 = bitcast i16* %"$foo" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  store i64 0, [2 x i8]* %tmpcast, align 8
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %2 = load i16, i16 addrspace(64)* null, align 536870912
  store i16 %2, i16* %"$foo", align 8
  %3 = bitcast i16* %Foo.x to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %3)
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i16* nonnull %Foo.x, i64 2, [2 x i8]* nonnull %tmpcast)
  %4 = load i16, i16* %Foo.x, align 2
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %3)
  %5 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %5)
  store i64 0, i64* %"@x_key", align 8
  %6 = zext i16 %4 to i64
  %7 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %7)
  store i64 %6, i64* %"@x_val", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo, i64* nonnull %"@x_key", i64* nonnull %"@x_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %5)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %7)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
)EXPECTED";

  test("struct Foo { short x; }"
       "kprobe:f"
       "{"
       "  $foo = (Foo)0;"
       "  @x = $foo.x;"
       "}",
       expected);

expected = R"EXPECTED(; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"kprobe:f"(i8* nocapture readnone) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %"@x_val" = alloca i64, align 8
  %"@x_key" = alloca i64, align 8
  %Foo.x = alloca i16, align 2
  %1 = bitcast i16* %Foo.x to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i16* nonnull %Foo.x, i64 2, i64 0)
  %2 = load i16, i16* %Foo.x, align 2
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  %3 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %3)
  store i64 0, i64* %"@x_key", align 8
  %4 = zext i16 %2 to i64
  %5 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %5)
  store i64 %4, i64* %"@x_val", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo, i64* nonnull %"@x_key", i64* nonnull %"@x_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %3)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %5)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
)EXPECTED";

  test("struct Foo { short x; }"
       "kprobe:f"
       "{"
       "  $foo = (Foo*)0;"
       "  @x = $foo->x;"
       "}",
       expected);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
