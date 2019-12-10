#include "common.h"
#include "../mocks.h"

using ::testing::Return;
using ::testing::_;

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, args_multiple_tracepoints)
{
  auto bpftrace = get_mock_bpftrace();

  test(*bpftrace,
       "tracepoint:sched:sched_one,tracepoint:sched:sched_two { "
       "@[args->common_field] = count(); }",

#if LLVM_VERSION_MAJOR > 6
       R"EXPECTED(; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"tracepoint:sched:sched_one"(i8*) local_unnamed_addr section "s_tracepoint:sched:sched_one_1" {
entry:
  %"@_val" = alloca i64, align 8
  %"@_key" = alloca [8 x i8], align 8
  %"struct _tracepoint_sched_sched_one.common_field" = alloca i64, align 8
  %1 = add i8* %0, i64 8
  %2 = bitcast i64* %"struct _tracepoint_sched_sched_one.common_field" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %2)
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i64* nonnull %"struct _tracepoint_sched_sched_one.common_field", i64 8, i8* %1)
  %3 = load i64, i64* %"struct _tracepoint_sched_sched_one.common_field", align 8
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %2)
  %4 = getelementptr inbounds [8 x i8], [8 x i8]* %"@_key", i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %4)
  store i64 %3, [8 x i8]* %"@_key", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i64 %pseudo, [8 x i8]* nonnull %"@_key")
  %map_lookup_cond = icmp eq i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_merge, label %lookup_success

lookup_success:                                   ; preds = %entry
  %5 = load i64, i8* %lookup_elem, align 8
  %phitmp = add i64 %5, 1
  br label %lookup_merge

lookup_merge:                                     ; preds = %entry, %lookup_success
  %lookup_elem_val.0 = phi i64 [ %phitmp, %lookup_success ], [ 1, %entry ]
  %6 = bitcast i64* %"@_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %6)
  store i64 %lookup_elem_val.0, i64* %"@_val", align 8
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo1, [8 x i8]* nonnull %"@_key", i64* nonnull %"@_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %4)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %6)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

define i64 @"tracepoint:sched:sched_two"(i8*) local_unnamed_addr section "s_tracepoint:sched:sched_two_2" {
entry:
  %"@_val" = alloca i64, align 8
  %"@_key" = alloca [8 x i8], align 8
  %"struct _tracepoint_sched_sched_two.common_field" = alloca i64, align 8
  %1 = add i8* %0, i64 16
  %2 = bitcast i64* %"struct _tracepoint_sched_sched_two.common_field" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %2)
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i64* nonnull %"struct _tracepoint_sched_sched_two.common_field", i64 8, i8* %1)
  %3 = load i64, i64* %"struct _tracepoint_sched_sched_two.common_field", align 8
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %2)
  %4 = getelementptr inbounds [8 x i8], [8 x i8]* %"@_key", i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %4)
  store i64 %3, [8 x i8]* %"@_key", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i64 %pseudo, [8 x i8]* nonnull %"@_key")
  %map_lookup_cond = icmp eq i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_merge, label %lookup_success

lookup_success:                                   ; preds = %entry
  %5 = load i64, i8* %lookup_elem, align 8
  %phitmp = add i64 %5, 1
  br label %lookup_merge

lookup_merge:                                     ; preds = %entry, %lookup_success
  %lookup_elem_val.0 = phi i64 [ %phitmp, %lookup_success ], [ 1, %entry ]
  %6 = bitcast i64* %"@_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %6)
  store i64 %lookup_elem_val.0, i64* %"@_val", align 8
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo1, [8 x i8]* nonnull %"@_key", i64* nonnull %"@_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %4)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %6)
  ret i64 0
}

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
)EXPECTED");
#else
       R"EXPECTED(; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"tracepoint:sched:sched_one"(i8*) local_unnamed_addr section "s_tracepoint:sched:sched_one_1" {
entry:
  %"@_val" = alloca i64, align 8
  %"@_key" = alloca [8 x i8], align 8
  %"struct _tracepoint_sched_sched_one.common_field" = alloca i64, align 8
  %1 = add i8* %0, i64 8
  %2 = bitcast i64* %"struct _tracepoint_sched_sched_one.common_field" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %2)
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i64* nonnull %"struct _tracepoint_sched_sched_one.common_field", i64 8, i8* %1)
  %3 = load i64, i64* %"struct _tracepoint_sched_sched_one.common_field", align 8
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %2)
  %4 = getelementptr inbounds [8 x i8], [8 x i8]* %"@_key", i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %4)
  store i64 %3, [8 x i8]* %"@_key", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i64 %pseudo, [8 x i8]* nonnull %"@_key")
  %map_lookup_cond = icmp eq i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_merge, label %lookup_success

lookup_success:                                   ; preds = %entry
  %5 = load i64, i8* %lookup_elem, align 8
  %phitmp = add i64 %5, 1
  br label %lookup_merge

lookup_merge:                                     ; preds = %entry, %lookup_success
  %lookup_elem_val.0 = phi i64 [ %phitmp, %lookup_success ], [ 1, %entry ]
  %6 = bitcast i64* %"@_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %6)
  store i64 %lookup_elem_val.0, i64* %"@_val", align 8
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo1, [8 x i8]* nonnull %"@_key", i64* nonnull %"@_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %4)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %6)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

define i64 @"tracepoint:sched:sched_two"(i8*) local_unnamed_addr section "s_tracepoint:sched:sched_two_2" {
entry:
  %"@_val" = alloca i64, align 8
  %"@_key" = alloca [8 x i8], align 8
  %"struct _tracepoint_sched_sched_two.common_field" = alloca i64, align 8
  %1 = add i8* %0, i64 16
  %2 = bitcast i64* %"struct _tracepoint_sched_sched_two.common_field" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %2)
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i64* nonnull %"struct _tracepoint_sched_sched_two.common_field", i64 8, i8* %1)
  %3 = load i64, i64* %"struct _tracepoint_sched_sched_two.common_field", align 8
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %2)
  %4 = getelementptr inbounds [8 x i8], [8 x i8]* %"@_key", i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %4)
  store i64 %3, [8 x i8]* %"@_key", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i64 %pseudo, [8 x i8]* nonnull %"@_key")
  %map_lookup_cond = icmp eq i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_merge, label %lookup_success

lookup_success:                                   ; preds = %entry
  %5 = load i64, i8* %lookup_elem, align 8
  %phitmp = add i64 %5, 1
  br label %lookup_merge

lookup_merge:                                     ; preds = %entry, %lookup_success
  %lookup_elem_val.0 = phi i64 [ %phitmp, %lookup_success ], [ 1, %entry ]
  %6 = bitcast i64* %"@_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %6)
  store i64 %lookup_elem_val.0, i64* %"@_val", align 8
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo1, [8 x i8]* nonnull %"@_key", i64* nonnull %"@_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %4)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %6)
  ret i64 0
}

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
)EXPECTED");
#endif
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
