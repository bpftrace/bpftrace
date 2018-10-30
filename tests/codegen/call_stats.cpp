#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_stats)
{
  test("kprobe:f { @x = stats(pid) }",

R"EXPECTED(; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"kprobe:f"(i8* nocapture readnone) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %"@x_val" = alloca i64, align 8
  %"@x_key2" = alloca i64, align 8
  %"@x_num" = alloca i64, align 8
  %"@x_key" = alloca i64, align 8
  %1 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  store i64 0, i64* %"@x_key", align 8
  %pseudo = tail call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i64 %pseudo, i64* nonnull %"@x_key")
  %map_lookup_cond = icmp eq i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_merge, label %lookup_success

lookup_success:                                   ; preds = %entry
  %2 = load i64, i8* %lookup_elem, align 8
  %phitmp = add i64 %2, 1
  br label %lookup_merge

lookup_merge:                                     ; preds = %entry, %lookup_success
  %lookup_elem_val.0 = phi i64 [ %phitmp, %lookup_success ], [ 1, %entry ]
  %3 = bitcast i64* %"@x_num" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %3)
  store i64 %lookup_elem_val.0, i64* %"@x_num", align 8
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo1, i64* nonnull %"@x_key", i64* nonnull %"@x_num", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %3)
  %4 = bitcast i64* %"@x_key2" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %4)
  store i64 1, i64* %"@x_key2", align 8
  %pseudo3 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem4 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i64 %pseudo3, i64* nonnull %"@x_key2")
  %map_lookup_cond9 = icmp eq i8* %lookup_elem4, null
  br i1 %map_lookup_cond9, label %lookup_merge7, label %lookup_success5

lookup_success5:                                  ; preds = %lookup_merge
  %5 = load i64, i8* %lookup_elem4, align 8
  br label %lookup_merge7

lookup_merge7:                                    ; preds = %lookup_merge, %lookup_success5
  %lookup_elem_val8.0 = phi i64 [ %5, %lookup_success5 ], [ 0, %lookup_merge ]
  %6 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %6)
  %get_pid_tgid = call i64 inttoptr (i64 14 to i64 ()*)()
  %7 = lshr i64 %get_pid_tgid, 32
  %8 = add i64 %7, %lookup_elem_val8.0
  store i64 %8, i64* %"@x_val", align 8
  %pseudo10 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem11 = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo10, i64* nonnull %"@x_key2", i64* nonnull %"@x_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %4)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %6)
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
