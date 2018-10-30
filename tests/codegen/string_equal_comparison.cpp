#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, string_equal_comparison)
{
  test("kretprobe:vfs_read /comm == \"sshd\"/ { @[comm] = count(); }",

R"EXPECTED(; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"kretprobe:vfs_read"(i8* nocapture readnone) local_unnamed_addr section "s_kretprobe:vfs_read_1" {
entry:
  %"@_val" = alloca i64, align 8
  %comm17 = alloca [16 x i8], align 1
  %"@_key" = alloca [16 x i8], align 1
  %strcmp.char14 = alloca i8, align 1
  %strcmp.char10 = alloca i8, align 1
  %strcmp.char6 = alloca i8, align 1
  %strcmp.char2 = alloca i8, align 1
  %strcmp.char = alloca i8, align 1
  %comm = alloca [16 x i8], align 1
  %1 = getelementptr inbounds [16 x i8], [16 x i8]* %comm, i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  call void @llvm.memset.p0i8.i64(i8* nonnull %1, i8 0, i64 16, i32 1, i1 false)
  %get_comm = call i64 inttoptr (i64 16 to i64 (i8*, i64)*)([16 x i8]* nonnull %comm, i64 16)
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %strcmp.char)
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char, i64 8, [16 x i8]* nonnull %comm)
  %2 = load i8, i8* %strcmp.char, align 1
  %strcmp.cmp = icmp eq i8 %2, 115
  br i1 %strcmp.cmp, label %strcmp.loop, label %pred_false.critedge

pred_false.critedge:                              ; preds = %entry
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  br label %pred_false

pred_false.critedge20:                            ; preds = %strcmp.loop
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  br label %pred_false

pred_false.critedge21:                            ; preds = %strcmp.loop1
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  br label %pred_false

pred_false.critedge22:                            ; preds = %strcmp.loop5
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  br label %pred_false

pred_false:                                       ; preds = %strcmp.loop9, %pred_false.critedge22, %pred_false.critedge21, %pred_false.critedge20, %pred_false.critedge
  ret i64 0

pred_true:                                        ; preds = %strcmp.loop9
  %3 = getelementptr inbounds [16 x i8], [16 x i8]* %"@_key", i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %3)
  %4 = getelementptr inbounds [16 x i8], [16 x i8]* %comm17, i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %4)
  call void @llvm.memset.p0i8.i64(i8* nonnull %4, i8 0, i64 16, i32 1, i1 false)
  %get_comm18 = call i64 inttoptr (i64 16 to i64 (i8*, i64)*)([16 x i8]* nonnull %comm17, i64 16)
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* nonnull %3, i8* nonnull %4, i64 16, i32 1, i1 false)
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i64 %pseudo, [16 x i8]* nonnull %"@_key")
  %map_lookup_cond = icmp eq i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_merge, label %lookup_success

strcmp.loop:                                      ; preds = %entry
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %strcmp.char2)
  %5 = add [16 x i8]* %comm, i64 1
  %probe_read3 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char2, i64 8, [16 x i8]* %5)
  %6 = load i8, i8* %strcmp.char2, align 1
  %strcmp.cmp4 = icmp eq i8 %6, 115
  br i1 %strcmp.cmp4, label %strcmp.loop1, label %pred_false.critedge20

strcmp.loop1:                                     ; preds = %strcmp.loop
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %strcmp.char6)
  %7 = add [16 x i8]* %comm, i64 2
  %probe_read7 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char6, i64 8, [16 x i8]* %7)
  %8 = load i8, i8* %strcmp.char6, align 1
  %strcmp.cmp8 = icmp eq i8 %8, 104
  br i1 %strcmp.cmp8, label %strcmp.loop5, label %pred_false.critedge21

strcmp.loop5:                                     ; preds = %strcmp.loop1
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %strcmp.char10)
  %9 = add [16 x i8]* %comm, i64 3
  %probe_read11 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char10, i64 8, [16 x i8]* %9)
  %10 = load i8, i8* %strcmp.char10, align 1
  %strcmp.cmp12 = icmp eq i8 %10, 100
  br i1 %strcmp.cmp12, label %strcmp.loop9, label %pred_false.critedge22

strcmp.loop9:                                     ; preds = %strcmp.loop5
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %strcmp.char14)
  %11 = add [16 x i8]* %comm, i64 4
  %probe_read15 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char14, i64 8, [16 x i8]* %11)
  %12 = load i8, i8* %strcmp.char14, align 1
  %strcmp.cmp16 = icmp eq i8 %12, 0
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  br i1 %strcmp.cmp16, label %pred_true, label %pred_false

lookup_success:                                   ; preds = %pred_true
  %13 = load i64, i8* %lookup_elem, align 8
  %phitmp = add i64 %13, 1
  br label %lookup_merge

lookup_merge:                                     ; preds = %pred_true, %lookup_success
  %lookup_elem_val.0 = phi i64 [ %phitmp, %lookup_success ], [ 1, %pred_true ]
  %14 = bitcast i64* %"@_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %14)
  store i64 %lookup_elem_val.0, i64* %"@_val", align 8
  %pseudo19 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo19, [16 x i8]* nonnull %"@_key", i64* nonnull %"@_val", i64 0)
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
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
