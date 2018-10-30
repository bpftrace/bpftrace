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
  %2 = icmp ugt i64 %get_pid_tgid, 281474976710655
  %3 = zext i1 %2 to i64
  %4 = shl nuw nsw i64 %3, 4
  %5 = lshr i64 %1, %4
  %6 = icmp sgt i64 %5, 255
  %7 = zext i1 %6 to i64
  %8 = shl nuw nsw i64 %7, 3
  %9 = lshr i64 %5, %8
  %10 = or i64 %8, %4
  %11 = icmp sgt i64 %9, 15
  %12 = zext i1 %11 to i64
  %13 = shl nuw nsw i64 %12, 2
  %14 = lshr i64 %9, %13
  %15 = or i64 %10, %13
  %16 = icmp sgt i64 %14, 3
  %17 = zext i1 %16 to i64
  %18 = shl nuw nsw i64 %17, 1
  %19 = lshr i64 %14, %18
  %20 = or i64 %15, %18
  %21 = icmp sgt i64 %19, 1
  %22 = zext i1 %21 to i64
  %23 = or i64 %20, %22
  %24 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %24)
  store i64 %23, i64* %"@x_key", align 8
  %pseudo = tail call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i64 %pseudo, i64* nonnull %"@x_key")
  %map_lookup_cond = icmp eq i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_merge, label %lookup_success

lookup_success:                                   ; preds = %entry
  %25 = load i64, i8* %lookup_elem, align 8
  %phitmp = add i64 %25, 1
  br label %lookup_merge

lookup_merge:                                     ; preds = %entry, %lookup_success
  %lookup_elem_val.0 = phi i64 [ %phitmp, %lookup_success ], [ 1, %entry ]
  %26 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %26)
  store i64 %lookup_elem_val.0, i64* %"@x_val", align 8
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo1, i64* nonnull %"@x_key", i64* nonnull %"@x_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %24)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %26)
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
