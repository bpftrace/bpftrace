#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, variable)
{
  test("kprobe:f { $var = comm; @x = $var; @y = $var }",

R"EXPECTED(; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"kprobe:f"(i8* nocapture readnone) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %"@y_key" = alloca i64, align 8
  %"@x_key" = alloca i64, align 8
  %"$var" = alloca [16 x i8], align 8
  %1 = getelementptr inbounds [16 x i8], [16 x i8]* %"$var", i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  store i64 0, [16 x i8]* %"$var", align 8
  %comm = alloca [16 x i8], align 1
  %2 = getelementptr inbounds [16 x i8], [16 x i8]* %comm, i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %2)
  call void @llvm.memset.p0i8.i64(i8* nonnull %2, i8 0, i64 16, i32 1, i1 false)
  %get_comm = call i64 inttoptr (i64 16 to i64 (i8*, i64)*)([16 x i8]* nonnull %comm, i64 16)
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* nonnull %1, i8* nonnull %2, i64 16, i32 1, i1 false)
  %3 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %3)
  store i64 0, i64* %"@x_key", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo, i64* nonnull %"@x_key", [16 x i8]* nonnull %"$var", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %3)
  %4 = bitcast i64* %"@y_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %4)
  store i64 0, i64* %"@y_key", align 8
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  %update_elem2 = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo1, i64* nonnull %"@y_key", [16 x i8]* nonnull %"$var", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %4)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i32, i1) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.memcpy.p0i8.p0i8.i64(i8* nocapture writeonly, i8* nocapture readonly, i64, i32, i1) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
)EXPECTED");
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
