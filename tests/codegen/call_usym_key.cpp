#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_usym_key)
{
  test("kprobe:f { @x[usym(0)] = count() }",

R"EXPECTED(; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"kprobe:f"(i8* nocapture readnone) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %"@x_val" = alloca i64, align 8
  %"@x_key" = alloca [16 x i8], align 8
  %1 = getelementptr inbounds [16 x i8], [16 x i8]* %"@x_key", i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %get_pid_tgid = tail call i64 inttoptr (i64 14 to i64 ()*)()
  %2 = lshr i64 %get_pid_tgid, 32
  %usym.sroa.0.0..sroa_cast = bitcast [16 x i8]* %"@x_key" to i64*
  store i64 0, i64* %usym.sroa.0.0..sroa_cast, align 8
  %usym.sroa.4.0..sroa_idx = getelementptr inbounds [16 x i8], [16 x i8]* %"@x_key", i64 0, i64 8
  %usym.sroa.4.0..sroa_cast = bitcast i8* %usym.sroa.4.0..sroa_idx to i64*
  store i64 %2, i64* %usym.sroa.4.0..sroa_cast, align 8
  %pseudo = tail call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i64 %pseudo, [16 x i8]* nonnull %"@x_key")
  %map_lookup_cond = icmp eq i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_merge, label %lookup_success

lookup_success:                                   ; preds = %entry
  %3 = load i64, i8* %lookup_elem, align 8
  %phitmp = add i64 %3, 1
  br label %lookup_merge

lookup_merge:                                     ; preds = %entry, %lookup_success
  %lookup_elem_val.0 = phi i64 [ %phitmp, %lookup_success ], [ 1, %entry ]
  %4 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %4)
  store i64 %lookup_elem_val.0, i64* %"@x_val", align 8
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo1, [16 x i8]* nonnull %"@x_key", i64* nonnull %"@x_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %4)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
)EXPECTED");
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
