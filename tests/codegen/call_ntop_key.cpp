#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_ntop_key)
{
  test("kprobe:f { @x[ntop(2, 0xFFFFFFFF)] = count()}",

#if LLVM_VERSION_MAJOR < 6
R"EXPECTED(; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"kprobe:f"(i8* nocapture readnone) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %"@x_val" = alloca i64, align 8
  %"@x_key" = alloca [24 x i8], align 8
  %1 = getelementptr inbounds [24 x i8], [24 x i8]* %"@x_key", i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %inet.sroa.0.0..sroa_cast = bitcast [24 x i8]* %"@x_key" to i64*
  store i64 2, i64* %inet.sroa.0.0..sroa_cast, align 8
  %inet.sroa.3.0..sroa_idx = getelementptr inbounds [24 x i8], [24 x i8]* %"@x_key", i64 0, i64 8
  %inet.sroa.3.0..sroa_cast = bitcast i8* %inet.sroa.3.0..sroa_idx to i32*
  store i32 -1, i32* %inet.sroa.3.0..sroa_cast, align 8
  %inet.sroa.5.0..sroa_idx = getelementptr inbounds [24 x i8], [24 x i8]* %"@x_key", i64 0, i64 12
  call void @llvm.memset.p0i8.i64(i8* %inet.sroa.5.0..sroa_idx, i8 0, i64 12, i32 4, i1 false)
  %pseudo = tail call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i8*, i64*)*)(i64 %pseudo, [24 x i8]* nonnull %"@x_key")
  %map_lookup_cond = icmp eq i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_merge, label %lookup_success

lookup_success:                                   ; preds = %entry
  %2 = load i64, i8* %lookup_elem, align 8
  %phitmp = add i64 %2, 1
  br label %lookup_merge

lookup_merge:                                     ; preds = %entry, %lookup_success
  %lookup_elem_val.0 = phi i64 [ %phitmp, %lookup_success ], [ 1, %entry ]
  %3 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %3)
  store i64 %lookup_elem_val.0, i64* %"@x_val", align 8
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i8*, i64*, [64 x i8]*, i64)*)(i64 %pseudo1, [24 x i8]* nonnull %"@x_key", i64* nonnull %"@x_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %3)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i32, i1) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
)EXPECTED");
#elif LLVM_VERSION_MAJOR > 6
R"EXPECTED(; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"kprobe:f"(i8* nocapture readnone) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %"@x_val" = alloca i64, align 8
  %"@x_key" = alloca [24 x i8], align 8
  %1 = getelementptr inbounds [24 x i8], [24 x i8]* %"@x_key", i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %inet.sroa.0.0..sroa_cast = bitcast [24 x i8]* %"@x_key" to i64*
  store i64 2, i64* %inet.sroa.0.0..sroa_cast, align 8
  %inet.sroa.3.0..sroa_idx = getelementptr inbounds [24 x i8], [24 x i8]* %"@x_key", i64 0, i64 8
  %inet.sroa.3.0..sroa_cast = bitcast i8* %inet.sroa.3.0..sroa_idx to i32*
  store i32 -1, i32* %inet.sroa.3.0..sroa_cast, align 8
  %inet.sroa.5.0..sroa_idx = getelementptr inbounds [24 x i8], [24 x i8]* %"@x_key", i64 0, i64 12
  call void @llvm.memset.p0i8.i64(i8* nonnull align 4 %inet.sroa.5.0..sroa_idx, i8 0, i64 12, i1 false)
  %pseudo = tail call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i8*, [24 x i8]*)*)(i64 %pseudo, [24 x i8]* nonnull %"@x_key")
  %map_lookup_cond = icmp eq i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_merge, label %lookup_success

lookup_success:                                   ; preds = %entry
  %2 = load i64, i8* %lookup_elem, align 8
  %phitmp = add i64 %2, 1
  br label %lookup_merge

lookup_merge:                                     ; preds = %entry, %lookup_success
  %lookup_elem_val.0 = phi i64 [ %phitmp, %lookup_success ], [ 1, %entry ]
  %3 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %3)
  store i64 %lookup_elem_val.0, i64* %"@x_val", align 8
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i8*, [24 x i8]*, i64*, i64)*)(i64 %pseudo1, [24 x i8]* nonnull %"@x_key", i64* nonnull %"@x_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %3)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i1) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
)EXPECTED");
#else
R"EXPECTED(; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"kprobe:f"(i8* nocapture readnone) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %"@x_val" = alloca i64, align 8
  %"@x_key" = alloca [24 x i8], align 8
  %1 = getelementptr inbounds [24 x i8], [24 x i8]* %"@x_key", i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %inet.sroa.0.0..sroa_cast = bitcast [24 x i8]* %"@x_key" to i64*
  store i64 2, i64* %inet.sroa.0.0..sroa_cast, align 8
  %inet.sroa.3.0..sroa_idx = getelementptr inbounds [24 x i8], [24 x i8]* %"@x_key", i64 0, i64 8
  %inet.sroa.3.0..sroa_cast = bitcast i8* %inet.sroa.3.0..sroa_idx to i32*
  store i32 -1, i32* %inet.sroa.3.0..sroa_cast, align 8
  %inet.sroa.5.0..sroa_idx = getelementptr inbounds [24 x i8], [24 x i8]* %"@x_key", i64 0, i64 12
  call void @llvm.memset.p0i8.i64(i8* nonnull %inet.sroa.5.0..sroa_idx, i8 0, i64 12, i32 4, i1 false)
  %pseudo = tail call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i8*, [24 x i8]*)*)(i64 %pseudo, [24 x i8]* nonnull %"@x_key")
  %map_lookup_cond = icmp eq i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_merge, label %lookup_success

lookup_success:                                   ; preds = %entry
  %2 = load i64, i8* %lookup_elem, align 8
  %phitmp = add i64 %2, 1
  br label %lookup_merge

lookup_merge:                                     ; preds = %entry, %lookup_success
  %lookup_elem_val.0 = phi i64 [ %phitmp, %lookup_success ], [ 1, %entry ]
  %3 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %3)
  store i64 %lookup_elem_val.0, i64* %"@x_val", align 8
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i8*, [24 x i8]*, i64*, i64)*)(i64 %pseudo1, [24 x i8]* nonnull %"@x_key", i64* nonnull %"@x_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %3)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i32, i1) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
)EXPECTED");
#endif
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
