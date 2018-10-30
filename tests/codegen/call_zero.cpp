#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_zero)
{
  test("BEGIN { @x = 1; } kprobe:f { zero(@x); }",

R"EXPECTED(; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @BEGIN(i8* nocapture readnone) local_unnamed_addr section "s_BEGIN_1" {
entry:
  %"@x_val" = alloca i64, align 8
  %"@x_key" = alloca i64, align 8
  %1 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  store i64 0, i64* %"@x_key", align 8
  %2 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %2)
  store i64 1, i64* %"@x_val", align 8
  %pseudo = tail call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo, i64* nonnull %"@x_key", i64* nonnull %"@x_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %2)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

define i64 @"kprobe:f"(i8*) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %perfdata = alloca [11 x i8], align 8
  %1 = getelementptr inbounds [11 x i8], [11 x i8]* %perfdata, i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  store i64 20003, [11 x i8]* %perfdata, align 8
  %str.sroa.0.0..sroa_idx = getelementptr inbounds [11 x i8], [11 x i8]* %perfdata, i64 0, i64 8
  store i8 64, i8* %str.sroa.0.0..sroa_idx, align 8
  %str.sroa.4.0..sroa_idx = getelementptr inbounds [11 x i8], [11 x i8]* %perfdata, i64 0, i64 9
  store i8 120, i8* %str.sroa.4.0..sroa_idx, align 1
  %str.sroa.5.0..sroa_idx = getelementptr inbounds [11 x i8], [11 x i8]* %perfdata, i64 0, i64 10
  store i8 0, i8* %str.sroa.5.0..sroa_idx, align 2
  %pseudo = tail call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  %get_cpu_id = tail call i64 inttoptr (i64 8 to i64 ()*)()
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i8*, i64, i8*, i64)*)(i8* %0, i64 %pseudo, i64 %get_cpu_id, [11 x i8]* nonnull %perfdata, i64 11)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  ret i64 0
}

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
)EXPECTED");
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
