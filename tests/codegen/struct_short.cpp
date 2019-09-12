#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, struct_short)
{
#if LLVM_VERSION_MAJOR > 6
  auto expected = R"EXPECTED(; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"kprobe:f"(i8* nocapture readnone) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %"@x_val" = alloca i64, align 8
  %"@x_key" = alloca i64, align 8
  %Foo.x = alloca i16, align 2
  %"$foo" = alloca i64, align 8
  %1 = bitcast i64* %"$foo" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %2 = bitcast i64* %"$foo" to i16*
  store i16 0, i16* %2, align 8
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %3 = load i16, i16 addrspace(64)* null, align 536870912
  store i16 %3, i16* %2, align 8
  %4 = bitcast i16* %Foo.x to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %4)
  %probe_read = call i64 inttoptr (i64 4 to i64 (i16*, i64, i8*)*)(i16* nonnull %Foo.x, i64 2, i8* nonnull %1)
  %5 = load i16, i16* %Foo.x, align 2
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %4)
  %6 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %6)
  store i64 0, i64* %"@x_key", align 8
  %7 = zext i16 %5 to i64
  %8 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %8)
  store i64 %7, i64* %"@x_val", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i8*, i64*, i64*, i64)*)(i64 %pseudo, i64* nonnull %"@x_key", i64* nonnull %"@x_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %6)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %8)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
)EXPECTED";
#else
  auto expected = R"EXPECTED(; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"kprobe:f"(i8* nocapture readnone) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %"@x_val" = alloca i64, align 8
  %"@x_key" = alloca i64, align 8
  %Foo.x = alloca i16, align 2
  %"$foo" = alloca i64, align 8
  %1 = bitcast i64* %"$foo" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %2 = bitcast i64* %"$foo" to i16*
  store i16 0, i16* %2, align 8
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %3 = load i16, i16 addrspace(64)* null, align 536870912
  store i16 %3, i16* %2, align 8
  %4 = bitcast i16* %Foo.x to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %4)
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i16* nonnull %Foo.x, i64 2, i8* nonnull %1)
  %5 = load i16, i16* %Foo.x, align 2
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %4)
  %6 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %6)
  store i64 0, i64* %"@x_key", align 8
  %7 = zext i16 %5 to i64
  %8 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %8)
  store i64 %7, i64* %"@x_val", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo, i64* nonnull %"@x_key", i64* nonnull %"@x_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %6)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %8)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
)EXPECTED";
#endif

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
  %probe_read = call i64 inttoptr (i64 4 to i64 (i16*, i64, i8*)*)(i16* nonnull %Foo.x, i64 2, i8* null)
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
  %update_elem = call i64 inttoptr (i64 2 to i64 (i8*, i64*, i64*, i64)*)(i64 %pseudo, i64* nonnull %"@x_key", i64* nonnull %"@x_val", i64 0)
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
