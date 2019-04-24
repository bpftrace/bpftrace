#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_ntop_char16)
{
  test("struct inet { unsigned char addr[16] } kprobe:f { @x[ntop(((inet*)0)->addr)]++}",

#if LLVM_VERSION_MAJOR > 6
R"EXPECTED(; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"kprobe:f"(i8* nocapture readnone) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %"@x_val" = alloca i64, align 8
  %inet2 = alloca [20 x i8], align 4
  %"@x_key1" = alloca [20 x i8], align 1
  %inet = alloca [20 x i8], align 4
  %"@x_key" = alloca [20 x i8], align 1
  %1 = getelementptr inbounds [20 x i8], [20 x i8]* %"@x_key", i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %2 = getelementptr inbounds [20 x i8], [20 x i8]* %inet, i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %2)
  store i32 10, [20 x i8]* %inet, align 4
  %3 = getelementptr inbounds [20 x i8], [20 x i8]* %inet, i64 0, i64 4
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %3, i64 16, i64 0)
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* nonnull align 1 %1, i8* nonnull align 4 %2, i64 20, i1 false)
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i64 %pseudo, [20 x i8]* nonnull %"@x_key")
  %map_lookup_cond = icmp eq i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_merge, label %lookup_success

lookup_success:                                   ; preds = %entry
  %4 = load i64, i8* %lookup_elem, align 8
  %phitmp = add i64 %4, 1
  br label %lookup_merge

lookup_merge:                                     ; preds = %entry, %lookup_success
  %lookup_elem_val.0 = phi i64 [ %phitmp, %lookup_success ], [ 1, %entry ]
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  %5 = getelementptr inbounds [20 x i8], [20 x i8]* %"@x_key1", i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %5)
  %6 = getelementptr inbounds [20 x i8], [20 x i8]* %inet2, i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %6)
  store i32 10, [20 x i8]* %inet2, align 4
  %7 = getelementptr inbounds [20 x i8], [20 x i8]* %inet2, i64 0, i64 4
  %probe_read3 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %7, i64 16, i64 0)
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* nonnull align 1 %5, i8* nonnull align 4 %6, i64 20, i1 false)
  %8 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %8)
  store i64 %lookup_elem_val.0, i64* %"@x_val", align 8
  %pseudo4 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo4, [20 x i8]* nonnull %"@x_key1", i64* nonnull %"@x_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %5)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %8)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.memcpy.p0i8.p0i8.i64(i8* nocapture writeonly, i8* nocapture readonly, i64, i1) #1

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
  %inet2 = alloca [20 x i8], align 4
  %"@x_key1" = alloca [20 x i8], align 1
  %inet = alloca [20 x i8], align 4
  %"@x_key" = alloca [20 x i8], align 1
  %1 = getelementptr inbounds [20 x i8], [20 x i8]* %"@x_key", i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %2 = getelementptr inbounds [20 x i8], [20 x i8]* %inet, i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %2)
  store i32 10, [20 x i8]* %inet, align 4
  %3 = getelementptr inbounds [20 x i8], [20 x i8]* %inet, i64 0, i64 4
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %3, i64 16, i64 0)
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* nonnull %1, i8* nonnull %2, i64 20, i32 1, i1 false)
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i64 %pseudo, [20 x i8]* nonnull %"@x_key")
  %map_lookup_cond = icmp eq i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_merge, label %lookup_success

lookup_success:                                   ; preds = %entry
  %4 = load i64, i8* %lookup_elem, align 8
  %phitmp = add i64 %4, 1
  br label %lookup_merge

lookup_merge:                                     ; preds = %entry, %lookup_success
  %lookup_elem_val.0 = phi i64 [ %phitmp, %lookup_success ], [ 1, %entry ]
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  %5 = getelementptr inbounds [20 x i8], [20 x i8]* %"@x_key1", i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %5)
  %6 = getelementptr inbounds [20 x i8], [20 x i8]* %inet2, i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %6)
  store i32 10, [20 x i8]* %inet2, align 4
  %7 = getelementptr inbounds [20 x i8], [20 x i8]* %inet2, i64 0, i64 4
  %probe_read3 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %7, i64 16, i64 0)
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* nonnull %5, i8* nonnull %6, i64 20, i32 1, i1 false)
  %8 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %8)
  store i64 %lookup_elem_val.0, i64* %"@x_val", align 8
  %pseudo4 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo4, [20 x i8]* nonnull %"@x_key1", i64* nonnull %"@x_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %5)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %8)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.memcpy.p0i8.p0i8.i64(i8* nocapture writeonly, i8* nocapture readonly, i64, i32, i1) #1

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


