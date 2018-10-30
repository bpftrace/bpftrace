#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, logical_or)
{
  test("kprobe:f { @x = pid == 1234 || pid == 1235 }",

R"EXPECTED(; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"kprobe:f"(i8* nocapture readnone) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %"@x_val" = alloca i64, align 8
  %"@x_key" = alloca i64, align 8
  %get_pid_tgid = tail call i64 inttoptr (i64 14 to i64 ()*)()
  %.mask = and i64 %get_pid_tgid, -4294967296
  %1 = icmp eq i64 %.mask, 5299989643264
  br i1 %1, label %"||_true", label %"||_lhs_false"

"||_lhs_false":                                   ; preds = %entry
  %get_pid_tgid1 = tail call i64 inttoptr (i64 14 to i64 ()*)()
  %.mask2 = and i64 %get_pid_tgid1, -4294967296
  %2 = icmp eq i64 %.mask2, 5304284610560
  br i1 %2, label %"||_true", label %"||_merge"

"||_true":                                        ; preds = %"||_lhs_false", %entry
  br label %"||_merge"

"||_merge":                                       ; preds = %"||_lhs_false", %"||_true"
  %"||_result.0" = phi i64 [ 1, %"||_true" ], [ 0, %"||_lhs_false" ]
  %3 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %3)
  store i64 0, i64* %"@x_key", align 8
  %4 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %4)
  store i64 %"||_result.0", i64* %"@x_val", align 8
  %pseudo = tail call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo, i64* nonnull %"@x_key", i64* nonnull %"@x_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %3)
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
