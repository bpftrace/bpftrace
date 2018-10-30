#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, struct_string_array)
{
  auto expected = R"EXPECTED(; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"kprobe:f"(i8* nocapture readnone) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %"@mystr_key" = alloca i64, align 8
  %Foo.str = alloca [32 x i8], align 1
  %"$foo" = alloca [32 x i8], align 8
  %1 = getelementptr inbounds [32 x i8], [32 x i8]* %"$foo", i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  store i64 0, [32 x i8]* %"$foo", align 8
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  call void @llvm.memcpy.p0i8.p64i8.i64(i8* nonnull %1, i8 addrspace(64)* null, i64 32, i32 8, i1 false)
  %2 = getelementptr inbounds [32 x i8], [32 x i8]* %Foo.str, i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %2)
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)([32 x i8]* nonnull %Foo.str, i64 32, [32 x i8]* nonnull %"$foo")
  %3 = bitcast i64* %"@mystr_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %3)
  store i64 0, i64* %"@mystr_key", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo, i64* nonnull %"@mystr_key", [32 x i8]* nonnull %Foo.str, i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %3)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %2)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.memcpy.p0i8.p64i8.i64(i8* nocapture writeonly, i8 addrspace(64)* nocapture readonly, i64, i32, i1) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
)EXPECTED";

  test("struct Foo { char str[32]; }"
       "kprobe:f"
       "{"
       "  $foo = (Foo)0;"
       "  @mystr = $foo.str;"
       "}",
       expected);

  expected = R"EXPECTED(; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"kprobe:f"(i8* nocapture readnone) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %"@mystr_key" = alloca i64, align 8
  %Foo.str = alloca [32 x i8], align 1
  %1 = getelementptr inbounds [32 x i8], [32 x i8]* %Foo.str, i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)([32 x i8]* nonnull %Foo.str, i64 32, i64 0)
  %2 = bitcast i64* %"@mystr_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %2)
  store i64 0, i64* %"@mystr_key", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo, i64* nonnull %"@mystr_key", [32 x i8]* nonnull %Foo.str, i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %2)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
)EXPECTED";

  test("struct Foo { char str[32]; }"
       "kprobe:f"
       "{"
       "  $foo = (Foo*)0;"
       "  @mystr = $foo->str;"
       "}",
       expected);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
