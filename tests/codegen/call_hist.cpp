#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_hist)
{
  test("kprobe:f { @x = hist(pid) }",

R"EXPECTED(; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"kprobe:f"(i8* nocapture readnone) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %"@x_val" = alloca i64, align 8
  %"@x_key" = alloca i64, align 8
  %get_pid_tgid = tail call i64 inttoptr (i64 14 to i64 ()*)()
  %1 = lshr i64 %get_pid_tgid, 32
  %2 = icmp eq i64 %1, 0
  br i1 %2, label %log2.exit, label %hist.is_not_zero.i

hist.is_not_zero.i:                               ; preds = %entry
  %3 = icmp ugt i64 %get_pid_tgid, 281474976710655
  %4 = zext i1 %3 to i64
  %5 = shl nuw nsw i64 %4, 4
  %6 = lshr i64 %1, %5
  %7 = icmp sgt i64 %6, 255
  %8 = zext i1 %7 to i64
  %9 = shl nuw nsw i64 %8, 3
  %10 = lshr i64 %6, %9
  %11 = icmp sgt i64 %10, 15
  %12 = zext i1 %11 to i64
  %13 = shl nuw nsw i64 %12, 2
  %14 = lshr i64 %10, %13
  %15 = or i64 %5, %9
  %16 = or i64 %15, %13
  %17 = or i64 %16, 2
  %18 = icmp sgt i64 %14, 3
  %19 = zext i1 %18 to i64
  %20 = shl nuw nsw i64 %19, 1
  %21 = lshr i64 %14, %20
  %22 = add nuw nsw i64 %20, %17
  %23 = icmp sgt i64 %21, 1
  %24 = zext i1 %23 to i64
  %25 = or i64 %22, %24
  br label %log2.exit

log2.exit:                                        ; preds = %entry, %hist.is_not_zero.i
  %log22 = phi i64 [ %25, %hist.is_not_zero.i ], [ 1, %entry ]
  %26 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %26)
  store i64 %log22, i64* %"@x_key", align 8
  %pseudo = tail call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i64 %pseudo, i64* nonnull %"@x_key")
  %map_lookup_cond = icmp eq i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_merge, label %lookup_success

lookup_success:                                   ; preds = %log2.exit
  %27 = load i64, i8* %lookup_elem, align 8
  %phitmp = add i64 %27, 1
  br label %lookup_merge

lookup_merge:                                     ; preds = %log2.exit, %lookup_success
  %lookup_elem_val.0 = phi i64 [ %phitmp, %lookup_success ], [ 1, %log2.exit ]
  %28 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %28)
  store i64 %lookup_elem_val.0, i64* %"@x_val", align 8
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo1, i64* nonnull %"@x_key", i64* nonnull %"@x_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %26)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %28)
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
