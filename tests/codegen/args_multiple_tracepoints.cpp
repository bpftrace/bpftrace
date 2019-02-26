#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, args_multiple_tracepoints)
{
  test("tracepoint:syscalls:sys_enter_open,tracepoint:syscalls:sys_enter_openat { @[str(args->filename)] = count(); }",

R"EXPECTED(; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"tracepoint:syscalls:sys_enter_open"(i8*) local_unnamed_addr section "s_tracepoint:syscalls:sys_enter_open_1" {
entry:
  %"@_val" = alloca i64, align 8
  %_tracepoint_syscalls_sys_enter_openat.filename = alloca i64, align 8
  %str = alloca [64 x i8], align 1
  %"@_key" = alloca [64 x i8], align 1
  %1 = getelementptr inbounds [64 x i8], [64 x i8]* %"@_key", i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %2 = getelementptr inbounds [64 x i8], [64 x i8]* %str, i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %2)
  call void @llvm.memset.p0i8.i64(i8* nonnull %2, i8 0, i64 64, i32 1, i1 false)
  %3 = add i8* %0, i64 16
  %4 = bitcast i64* %_tracepoint_syscalls_sys_enter_openat.filename to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %4)
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i64* nonnull %_tracepoint_syscalls_sys_enter_openat.filename, i64 8, i8* %3)
  %5 = load i64, i64* %_tracepoint_syscalls_sys_enter_openat.filename, align 8
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %4)
  %probe_read_str = call i64 inttoptr (i64 45 to i64 (i8*, i64, i8*)*)([64 x i8]* nonnull %str, i64 64, i64 %5)
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* nonnull %1, i8* nonnull %2, i64 64, i32 1, i1 false)
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i64 %pseudo, [64 x i8]* nonnull %"@_key")
  %map_lookup_cond = icmp eq i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_merge, label %lookup_success

lookup_success:                                   ; preds = %entry
  %6 = load i64, i8* %lookup_elem, align 8
  %phitmp = add i64 %6, 1
  br label %lookup_merge

lookup_merge:                                     ; preds = %entry, %lookup_success
  %lookup_elem_val.0 = phi i64 [ %phitmp, %lookup_success ], [ 1, %entry ]
  %7 = bitcast i64* %"@_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %7)
  store i64 %lookup_elem_val.0, i64* %"@_val", align 8
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo1, [64 x i8]* nonnull %"@_key", i64* nonnull %"@_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %7)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i32, i1) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.memcpy.p0i8.p0i8.i64(i8* nocapture writeonly, i8* nocapture readonly, i64, i32, i1) #1

define i64 @"tracepoint:syscalls:sys_enter_openat"(i8*) local_unnamed_addr section "s_tracepoint:syscalls:sys_enter_openat_2" {
entry:
  %"@_val" = alloca i64, align 8
  %_tracepoint_syscalls_sys_enter_openat.filename = alloca i64, align 8
  %str = alloca [64 x i8], align 1
  %"@_key" = alloca [64 x i8], align 1
  %1 = getelementptr inbounds [64 x i8], [64 x i8]* %"@_key", i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %2 = getelementptr inbounds [64 x i8], [64 x i8]* %str, i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %2)
  call void @llvm.memset.p0i8.i64(i8* nonnull %2, i8 0, i64 64, i32 1, i1 false)
  %3 = add i8* %0, i64 24
  %4 = bitcast i64* %_tracepoint_syscalls_sys_enter_openat.filename to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %4)
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i64* nonnull %_tracepoint_syscalls_sys_enter_openat.filename, i64 8, i8* %3)
  %5 = load i64, i64* %_tracepoint_syscalls_sys_enter_openat.filename, align 8
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %4)
  %probe_read_str = call i64 inttoptr (i64 45 to i64 (i8*, i64, i8*)*)([64 x i8]* nonnull %str, i64 64, i64 %5)
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* nonnull %1, i8* nonnull %2, i64 64, i32 1, i1 false)
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i64 %pseudo, [64 x i8]* nonnull %"@_key")
  %map_lookup_cond = icmp eq i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_merge, label %lookup_success

lookup_success:                                   ; preds = %entry
  %6 = load i64, i8* %lookup_elem, align 8
  %phitmp = add i64 %6, 1
  br label %lookup_merge

lookup_merge:                                     ; preds = %entry, %lookup_success
  %lookup_elem_val.0 = phi i64 [ %phitmp, %lookup_success ], [ 1, %entry ]
  %7 = bitcast i64* %"@_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %7)
  store i64 %lookup_elem_val.0, i64* %"@_val", align 8
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo1, [64 x i8]* nonnull %"@_key", i64* nonnull %"@_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %7)
  ret i64 0
}

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
)EXPECTED");
}

TEST(codegen, args_multiple_tracepoints_wild)
{
  test("tracepoint:syscalls:sys_enter_recv* { @[args->flags] = count(); }",

R"EXPECTED(; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"tracepoint:syscalls:sys_enter_recvfrom"(i8*) local_unnamed_addr section "s_tracepoint:syscalls:sys_enter_recvfrom_1" {
entry:
  %"@_val" = alloca i64, align 8
  %_tracepoint_syscalls_sys_enter_recvfrom.flags = alloca i64, align 8
  %"@_key" = alloca [8 x i8], align 8
  %1 = getelementptr inbounds [8 x i8], [8 x i8]* %"@_key", i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %2 = add i8* %0, i64 40
  %3 = bitcast i64* %_tracepoint_syscalls_sys_enter_recvfrom.flags to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %3)
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i64* nonnull %_tracepoint_syscalls_sys_enter_recvfrom.flags, i64 8, i8* %2)
  %4 = load i64, i64* %_tracepoint_syscalls_sys_enter_recvfrom.flags, align 8
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %3)
  store i64 %4, i8* %1, align 8
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
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %6)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

define i64 @"tracepoint:syscalls:sys_enter_recvmmsg"(i8*) local_unnamed_addr section "s_tracepoint:syscalls:sys_enter_recvmmsg_2" {
entry:
  %"@_val" = alloca i64, align 8
  %_tracepoint_syscalls_sys_enter_recvfrom.flags = alloca i64, align 8
  %"@_key" = alloca [8 x i8], align 8
  %1 = getelementptr inbounds [8 x i8], [8 x i8]* %"@_key", i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %2 = add i8* %0, i64 40
  %3 = bitcast i64* %_tracepoint_syscalls_sys_enter_recvfrom.flags to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %3)
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i64* nonnull %_tracepoint_syscalls_sys_enter_recvfrom.flags, i64 8, i8* %2)
  %4 = load i64, i64* %_tracepoint_syscalls_sys_enter_recvfrom.flags, align 8
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %3)
  store i64 %4, i8* %1, align 8
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
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %6)
  ret i64 0
}

define i64 @"tracepoint:syscalls:sys_enter_recvmsg"(i8*) local_unnamed_addr section "s_tracepoint:syscalls:sys_enter_recvmsg_3" {
entry:
  %"@_val" = alloca i64, align 8
  %_tracepoint_syscalls_sys_enter_recvfrom.flags = alloca i64, align 8
  %"@_key" = alloca [8 x i8], align 8
  %1 = getelementptr inbounds [8 x i8], [8 x i8]* %"@_key", i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %2 = add i8* %0, i64 32
  %3 = bitcast i64* %_tracepoint_syscalls_sys_enter_recvfrom.flags to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %3)
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i64* nonnull %_tracepoint_syscalls_sys_enter_recvfrom.flags, i64 8, i8* %2)
  %4 = load i64, i64* %_tracepoint_syscalls_sys_enter_recvfrom.flags, align 8
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %3)
  store i64 %4, i8* %1, align 8
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
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %6)
  ret i64 0
}

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
)EXPECTED");
}

} // namespace codegen
} // namespace test
} // namespace bpftrace

