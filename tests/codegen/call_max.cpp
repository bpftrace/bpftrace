#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_max)
{
  test("kprobe:f { @x = max(pid) }",

R"EXPECTED(; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"kprobe:f"(i8* nocapture readnone) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %"@x_val" = alloca i64, align 8
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
  br label %lookup_merge

lookup_merge:                                     ; preds = %entry, %lookup_success
  %lookup_elem_val.0 = phi i64 [ %2, %lookup_success ], [ 0, %entry ]
  %3 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %3)
  %get_pid_tgid = call i64 inttoptr (i64 14 to i64 ()*)()
  %4 = lshr i64 %get_pid_tgid, 32
  %5 = icmp slt i64 %4, %lookup_elem_val.0
  br i1 %5, label %min.lt, label %min.ge

min.lt:                                           ; preds = %lookup_merge, %min.ge
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %3)
  ret i64 0

min.ge:                                           ; preds = %lookup_merge
  store i64 %4, i64* %"@x_val", align 8
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo1, i64* nonnull %"@x_key", i64* nonnull %"@x_val", i64 0)
  br label %min.lt
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
