#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, string_not_equal_comparison)
{
  test("kretprobe:vfs_read /comm != \"sshd\"/ { @[comm] = count(); }",

#if LLVM_VERSION_MAJOR > 6
R"EXPECTED(; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"kretprobe:vfs_read"(i8* nocapture readnone) local_unnamed_addr section "s_kretprobe:vfs_read_1" {
entry:
  %"@_val" = alloca i64, align 8
  %comm9 = alloca [16 x i8], align 1
  %"@_key" = alloca [16 x i8], align 1
  %comm = alloca [16 x i8], align 1
  %1 = getelementptr inbounds [16 x i8], [16 x i8]* %comm, i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  call void @llvm.memset.p0i8.i64(i8* nonnull align 1 %1, i8 0, i64 16, i1 false)
  %get_comm = call i64 inttoptr (i64 16 to i64 (i8*, i64)*)([16 x i8]* nonnull %comm, i64 16)
  %2 = load i8, [16 x i8]* %comm, align 1
  %strcmp.cmp = icmp eq i8 %2, 115
  br i1 %strcmp.cmp, label %strcmp.loop, label %pred_true

pred_false:                                       ; preds = %strcmp.loop5
  ret i64 0

pred_true:                                        ; preds = %strcmp.loop5, %strcmp.loop3, %strcmp.loop1, %strcmp.loop, %entry
  %3 = getelementptr inbounds [16 x i8], [16 x i8]* %"@_key", i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %3)
  %4 = getelementptr inbounds [16 x i8], [16 x i8]* %comm9, i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %4)
  call void @llvm.memset.p0i8.i64(i8* nonnull align 1 %4, i8 0, i64 16, i1 false)
  %get_comm10 = call i64 inttoptr (i64 16 to i64 (i8*, i64)*)([16 x i8]* nonnull %comm9, i64 16)
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* nonnull align 1 %3, i8* nonnull align 1 %4, i64 16, i1 false)
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i64 %pseudo, [16 x i8]* nonnull %"@_key")
  %map_lookup_cond = icmp eq i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_merge, label %lookup_success

strcmp.loop:                                      ; preds = %entry
  %5 = add [16 x i8]* %comm, i64 1
  %6 = load i8, [16 x i8]* %5, align 1
  %strcmp.cmp2 = icmp eq i8 %6, 115
  br i1 %strcmp.cmp2, label %strcmp.loop1, label %pred_true

strcmp.loop1:                                     ; preds = %strcmp.loop
  %7 = add [16 x i8]* %comm, i64 2
  %8 = load i8, [16 x i8]* %7, align 1
  %strcmp.cmp4 = icmp eq i8 %8, 104
  br i1 %strcmp.cmp4, label %strcmp.loop3, label %pred_true

strcmp.loop3:                                     ; preds = %strcmp.loop1
  %9 = add [16 x i8]* %comm, i64 3
  %10 = load i8, [16 x i8]* %9, align 1
  %strcmp.cmp6 = icmp eq i8 %10, 100
  br i1 %strcmp.cmp6, label %strcmp.loop5, label %pred_true

strcmp.loop5:                                     ; preds = %strcmp.loop3
  %11 = add [16 x i8]* %comm, i64 4
  %12 = load i8, [16 x i8]* %11, align 1
  %strcmp.cmp8 = icmp eq i8 %12, 0
  br i1 %strcmp.cmp8, label %pred_false, label %pred_true

lookup_success:                                   ; preds = %pred_true
  %13 = load i64, i8* %lookup_elem, align 8
  %phitmp = add i64 %13, 1
  br label %lookup_merge

lookup_merge:                                     ; preds = %pred_true, %lookup_success
  %lookup_elem_val.0 = phi i64 [ %phitmp, %lookup_success ], [ 1, %pred_true ]
  %14 = bitcast i64* %"@_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %14)
  store i64 %lookup_elem_val.0, i64* %"@_val", align 8
  %pseudo11 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo11, [16 x i8]* nonnull %"@_key", i64* nonnull %"@_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %3)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %14)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i1) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.memcpy.p0i8.p0i8.i64(i8* nocapture writeonly, i8* nocapture readonly, i64, i1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
)EXPECTED");
#else
R"EXPECTED(; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"kretprobe:vfs_read"(i8* nocapture readnone) local_unnamed_addr section "s_kretprobe:vfs_read_1" {
entry:
  %"@_val" = alloca i64, align 8
  %comm9 = alloca [16 x i8], align 1
  %"@_key" = alloca [16 x i8], align 1
  %comm = alloca [16 x i8], align 1
  %1 = getelementptr inbounds [16 x i8], [16 x i8]* %comm, i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  call void @llvm.memset.p0i8.i64(i8* nonnull %1, i8 0, i64 16, i32 1, i1 false)
  %get_comm = call i64 inttoptr (i64 16 to i64 (i8*, i64)*)([16 x i8]* nonnull %comm, i64 16)
  %2 = load i8, [16 x i8]* %comm, align 1
  %strcmp.cmp = icmp eq i8 %2, 115
  br i1 %strcmp.cmp, label %strcmp.loop, label %pred_true

pred_false:                                       ; preds = %strcmp.loop5
  ret i64 0

pred_true:                                        ; preds = %strcmp.loop5, %strcmp.loop3, %strcmp.loop1, %strcmp.loop, %entry
  %3 = getelementptr inbounds [16 x i8], [16 x i8]* %"@_key", i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %3)
  %4 = getelementptr inbounds [16 x i8], [16 x i8]* %comm9, i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %4)
  call void @llvm.memset.p0i8.i64(i8* nonnull %4, i8 0, i64 16, i32 1, i1 false)
  %get_comm10 = call i64 inttoptr (i64 16 to i64 (i8*, i64)*)([16 x i8]* nonnull %comm9, i64 16)
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* nonnull %3, i8* nonnull %4, i64 16, i32 1, i1 false)
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i64 %pseudo, [16 x i8]* nonnull %"@_key")
  %map_lookup_cond = icmp eq i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_merge, label %lookup_success

strcmp.loop:                                      ; preds = %entry
  %5 = add [16 x i8]* %comm, i64 1
  %6 = load i8, [16 x i8]* %5, align 1
  %strcmp.cmp2 = icmp eq i8 %6, 115
  br i1 %strcmp.cmp2, label %strcmp.loop1, label %pred_true

strcmp.loop1:                                     ; preds = %strcmp.loop
  %7 = add [16 x i8]* %comm, i64 2
  %8 = load i8, [16 x i8]* %7, align 1
  %strcmp.cmp4 = icmp eq i8 %8, 104
  br i1 %strcmp.cmp4, label %strcmp.loop3, label %pred_true

strcmp.loop3:                                     ; preds = %strcmp.loop1
  %9 = add [16 x i8]* %comm, i64 3
  %10 = load i8, [16 x i8]* %9, align 1
  %strcmp.cmp6 = icmp eq i8 %10, 100
  br i1 %strcmp.cmp6, label %strcmp.loop5, label %pred_true

strcmp.loop5:                                     ; preds = %strcmp.loop3
  %11 = add [16 x i8]* %comm, i64 4
  %12 = load i8, [16 x i8]* %11, align 1
  %strcmp.cmp8 = icmp eq i8 %12, 0
  br i1 %strcmp.cmp8, label %pred_false, label %pred_true

lookup_success:                                   ; preds = %pred_true
  %13 = load i64, i8* %lookup_elem, align 8
  %phitmp = add i64 %13, 1
  br label %lookup_merge

lookup_merge:                                     ; preds = %pred_true, %lookup_success
  %lookup_elem_val.0 = phi i64 [ %phitmp, %lookup_success ], [ 1, %pred_true ]
  %14 = bitcast i64* %"@_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %14)
  store i64 %lookup_elem_val.0, i64* %"@_val", align 8
  %pseudo11 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo11, [16 x i8]* nonnull %"@_key", i64* nonnull %"@_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %3)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %14)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i32, i1) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.memcpy.p0i8.p0i8.i64(i8* nocapture writeonly, i8* nocapture readonly, i64, i32, i1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
)EXPECTED");
#endif
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
