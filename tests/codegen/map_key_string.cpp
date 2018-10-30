#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, map_key_string)
{
  test("kprobe:f { @x[\"a\", \"b\"] = 44 }",

R"EXPECTED(; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"kprobe:f"(i8* nocapture readnone) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %"@x_val" = alloca i64, align 8
  %"@x_key" = alloca [128 x i8], align 1
  %1 = getelementptr inbounds [128 x i8], [128 x i8]* %"@x_key", i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  store i8 97, i8* %1, align 1
  %str.sroa.3.0..sroa_idx = getelementptr inbounds [128 x i8], [128 x i8]* %"@x_key", i64 0, i64 1
  %str1.sroa.0.0..sroa_idx = getelementptr inbounds [128 x i8], [128 x i8]* %"@x_key", i64 0, i64 64
  call void @llvm.memset.p0i8.i64(i8* %str.sroa.3.0..sroa_idx, i8 0, i64 63, i32 1, i1 false)
  store i8 98, i8* %str1.sroa.0.0..sroa_idx, align 1
  %str1.sroa.3.0..sroa_idx = getelementptr inbounds [128 x i8], [128 x i8]* %"@x_key", i64 0, i64 65
  %2 = bitcast i64* %"@x_val" to i8*
  call void @llvm.memset.p0i8.i64(i8* %str1.sroa.3.0..sroa_idx, i8 0, i64 63, i32 1, i1 false)
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %2)
  store i64 44, i64* %"@x_val", align 8
  %pseudo = tail call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo, [128 x i8]* nonnull %"@x_key", i64* nonnull %"@x_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %2)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i32, i1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
)EXPECTED");
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
