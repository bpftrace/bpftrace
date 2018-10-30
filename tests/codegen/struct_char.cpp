#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, struct_char)
{
  auto expected = R"EXPECTED(; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"kprobe:f"(i8* nocapture readnone) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %"@x_val" = alloca i64, align 8
  %"@x_key" = alloca i64, align 8
  %Foo.x = alloca i8, align 1
  %"$foo" = alloca [1 x i8], align 8
  %1 = getelementptr inbounds [1 x i8], [1 x i8]* %"$foo", i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  store i64 0, [1 x i8]* %"$foo", align 8
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %2 = load i8, i8 addrspace(64)* null, align 536870912
  store i8 %2, i8* %1, align 8
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %Foo.x)
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %Foo.x, i64 1, [1 x i8]* nonnull %"$foo")
  %3 = load i8, i8* %Foo.x, align 1
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %Foo.x)
  %4 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %4)
  store i64 0, i64* %"@x_key", align 8
  %5 = zext i8 %3 to i64
  %6 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %6)
  store i64 %5, i64* %"@x_val", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo, i64* nonnull %"@x_key", i64* nonnull %"@x_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %4)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %6)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
)EXPECTED";

  test("struct Foo { char x; }"
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
  %Foo.x = alloca i8, align 1
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %Foo.x)
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %Foo.x, i64 1, i64 0)
  %1 = load i8, i8* %Foo.x, align 1
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %Foo.x)
  %2 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %2)
  store i64 0, i64* %"@x_key", align 8
  %3 = zext i8 %1 to i64
  %4 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %4)
  store i64 %3, i64* %"@x_val", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo, i64* nonnull %"@x_key", i64* nonnull %"@x_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %2)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %4)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
)EXPECTED";

  test("struct Foo { char x; }"
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
