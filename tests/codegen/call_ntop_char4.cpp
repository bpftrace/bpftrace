#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_ntop_char4)
{
  test("struct inet { unsigned char addr[4] } kprobe:f { @x[ntop(((inet*)0)->addr)]++}",

R"EXPECTED(; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"kprobe:f"(i8* nocapture readnone) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %"@x_val" = alloca i64, align 8
  %inet2 = alloca i64, align 8
  %tmpcast7 = bitcast i64* %inet2 to [8 x i8]*
  %"@x_key1" = alloca i64, align 8
  %tmpcast6 = bitcast i64* %"@x_key1" to [8 x i8]*
  %inet = alloca i64, align 8
  %tmpcast5 = bitcast i64* %inet to [8 x i8]*
  %"@x_key" = alloca i64, align 8
  %tmpcast = bitcast i64* %"@x_key" to [8 x i8]*
  %1 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %2 = bitcast i64* %inet to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %2)
  store i32 2, [8 x i8]* %tmpcast5, align 8
  %3 = getelementptr inbounds [8 x i8], [8 x i8]* %tmpcast5, i64 0, i64 4
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %3, i64 4, i64 0)
  %4 = load i64, i64* %inet, align 8
  store i64 %4, i64* %"@x_key", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i64 %pseudo, [8 x i8]* nonnull %tmpcast)
  %map_lookup_cond = icmp eq i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_merge, label %lookup_success

lookup_success:                                   ; preds = %entry
  %5 = load i64, i8* %lookup_elem, align 8
  %phitmp = add i64 %5, 1
  br label %lookup_merge

lookup_merge:                                     ; preds = %entry, %lookup_success
  %lookup_elem_val.0 = phi i64 [ %phitmp, %lookup_success ], [ 1, %entry ]
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  %6 = bitcast i64* %"@x_key1" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %6)
  %7 = bitcast i64* %inet2 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %7)
  store i32 2, [8 x i8]* %tmpcast7, align 8
  %8 = getelementptr inbounds [8 x i8], [8 x i8]* %tmpcast7, i64 0, i64 4
  %probe_read3 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %8, i64 4, i64 0)
  %9 = load i64, i64* %inet2, align 8
  store i64 %9, i64* %"@x_key1", align 8
  %10 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %10)
  store i64 %lookup_elem_val.0, i64* %"@x_val", align 8
  %pseudo4 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo4, [8 x i8]* nonnull %tmpcast6, i64* nonnull %"@x_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %6)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %10)
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

