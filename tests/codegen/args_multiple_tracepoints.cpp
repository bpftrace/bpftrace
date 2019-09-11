#include "common.h"

using ::testing::Return;
using ::testing::_;

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, args_multiple_tracepoints)
{
  std::set<std::string> wildcard_matches = {
    "sys_enter_open",
    "sys_enter_openat"
  };
  MockBPFtrace bpftrace;
  ON_CALL(bpftrace, find_wildcard_matches(_, _, _))
    .WillByDefault(Return(wildcard_matches));
  ON_CALL(bpftrace, add_probe(_))
    .WillByDefault(Return(0));

  std::string sys_enter_open_input =
    "name: sys_enter_open\n"
    "ID: 602\n"
    "format:\n"
    "	field:unsigned short common_type;	offset:0;	size:2;	signed:0;\n"
    "	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;\n"
    "	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;\n"
    "	field:int common_pid;	offset:4;	size:4;	signed:1;\n"
    "\n"
    "	field:long __syscall_nr;	offset:8;	size:4;	signed:1;\n"
    "	field:const char * filename;	offset:16;	size:8;	signed:0;\n"
    "	field:long flags;	offset:24;	size:8;	signed:0;\n"
    "	field:long mode;	offset:32;	size:8;	signed:0;\n"
    "\n"
    "print fmt: \"filename: 0x%08lx, flags: 0x%08lx, mode: 0x%08lx\", ((unsigned long)(REC->filename)), ((unsigned long)(REC->flags)), ((unsigned long)(REC->mode))\n";
  std::istringstream sys_enter_open_format_file(sys_enter_open_input);
  std::string sys_enter_open_struct = MockTracepointFormatParser::get_tracepoint_struct_public(sys_enter_open_format_file, "syscalls", "sys_enter_open");

  std::string sys_enter_openat_input =
    "name: sys_enter_openat\n"
    "ID: 600\n"
    "format:\n"
    "	field:unsigned short common_type;	offset:0;	size:2;	signed:0;\n"
    "	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;\n"
    "	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;\n"
    "	field:int common_pid;	offset:4;	size:4;	signed:1;\n"
    "\n"
    "	field:int __syscall_nr;	offset:8;	size:4;	signed:1;\n"
    "	field:long dfd;	offset:16;	size:8;	signed:0;\n"
    "	field:const char * filename;	offset:24;	size:8;	signed:0;\n"
    "	field:long flags;	offset:32;	size:8;	signed:0;\n"
    "	field:long mode;	offset:40;	size:8;	signed:0;\n"
    "\n"
    "print fmt: \"dfd: 0x%08lx, filename: 0x%08lx, flags: 0x%08lx, mode: 0x%08lx\", ((unsigned long)(REC->dfd)), ((unsigned long)(REC->filename)), ((unsigned long)(REC->flags)), ((unsigned long)(REC->mode))\n";
  std::istringstream sys_enter_openat_format_file(sys_enter_openat_input);
  std::string sys_enter_openat_struct = MockTracepointFormatParser::get_tracepoint_struct_public(sys_enter_openat_format_file, "syscalls", "sys_enter_openat");

  test(
      bpftrace,
      sys_enter_open_struct + sys_enter_openat_struct +
      "tracepoint:syscalls:sys_enter_open,tracepoint:syscalls:sys_enter_openat { @[str(args->filename)] = count(); }",

#if LLVM_VERSION_MAJOR > 6
R"EXPECTED(; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"tracepoint:syscalls:sys_enter_open"(i8*) local_unnamed_addr section "s_tracepoint:syscalls:sys_enter_open_1" {
entry:
  %"@_val" = alloca i64, align 8
  %_tracepoint_syscalls_sys_enter_open.filename = alloca i64, align 8
  %str = alloca [64 x i8], align 1
  %"@_key" = alloca [64 x i8], align 1
  %1 = getelementptr inbounds [64 x i8], [64 x i8]* %"@_key", i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %2 = getelementptr inbounds [64 x i8], [64 x i8]* %str, i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %2)
  call void @llvm.memset.p0i8.i64(i8* nonnull align 1 %2, i8 0, i64 64, i1 false)
  %3 = ptrtoint i8* %0 to i64
  %4 = add i64 %3, 16
  %5 = inttoptr i64 %4 to i8*
  %6 = bitcast i64* %_tracepoint_syscalls_sys_enter_open.filename to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %6)
  %probe_read = call i64 inttoptr (i64 4 to i64 (i64*, i64, i8*)*)(i64* nonnull %_tracepoint_syscalls_sys_enter_open.filename, i64 8, i8* %5)
  %7 = load i64, i64* %_tracepoint_syscalls_sys_enter_open.filename, align 8
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %6)
  %probe_read_str = call i64 inttoptr (i64 45 to i64 (i8*, i64, i8*)*)([64 x i8]* nonnull %str, i64 64, i64 %7)
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* nonnull align 1 %1, i8* nonnull align 1 %2, i64 64, i1 false)
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i8*, [64 x i8]*)*)(i64 %pseudo, [64 x i8]* nonnull %"@_key")
  %map_lookup_cond = icmp eq i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_merge, label %lookup_success

lookup_success:                                   ; preds = %entry
  %8 = load i64, i8* %lookup_elem, align 8
  %phitmp = add i64 %8, 1
  br label %lookup_merge

lookup_merge:                                     ; preds = %entry, %lookup_success
  %lookup_elem_val.0 = phi i64 [ %phitmp, %lookup_success ], [ 1, %entry ]
  %9 = bitcast i64* %"@_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %9)
  store i64 %lookup_elem_val.0, i64* %"@_val", align 8
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i8*, [64 x i8]*, i64*, i64)*)(i64 %pseudo1, [64 x i8]* nonnull %"@_key", i64* nonnull %"@_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %9)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i1) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.memcpy.p0i8.p0i8.i64(i8* nocapture writeonly, i8* nocapture readonly, i64, i1) #1

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
  call void @llvm.memset.p0i8.i64(i8* nonnull align 1 %2, i8 0, i64 64, i1 false)
  %3 = ptrtoint i8* %0 to i64
  %4 = add i64 %3, 24
  %5 = inttoptr i64 %4 to i8*
  %6 = bitcast i64* %_tracepoint_syscalls_sys_enter_openat.filename to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %6)
  %probe_read = call i64 inttoptr (i64 4 to i64 (i64*, i64, i8*)*)(i64* nonnull %_tracepoint_syscalls_sys_enter_openat.filename, i64 8, i8* %5)
  %7 = load i64, i64* %_tracepoint_syscalls_sys_enter_openat.filename, align 8
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %6)
  %probe_read_str = call i64 inttoptr (i64 45 to i64 (i8*, i64, i8*)*)([64 x i8]* nonnull %str, i64 64, i64 %7)
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* nonnull align 1 %1, i8* nonnull align 1 %2, i64 64, i1 false)
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i8*, [64 x i8]*)*)(i64 %pseudo, [64 x i8]* nonnull %"@_key")
  %map_lookup_cond = icmp eq i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_merge, label %lookup_success

lookup_success:                                   ; preds = %entry
  %8 = load i64, i8* %lookup_elem, align 8
  %phitmp = add i64 %8, 1
  br label %lookup_merge

lookup_merge:                                     ; preds = %entry, %lookup_success
  %lookup_elem_val.0 = phi i64 [ %phitmp, %lookup_success ], [ 1, %entry ]
  %9 = bitcast i64* %"@_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %9)
  store i64 %lookup_elem_val.0, i64* %"@_val", align 8
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i8*, [64 x i8]*, i64*, i64)*)(i64 %pseudo1, [64 x i8]* nonnull %"@_key", i64* nonnull %"@_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %9)
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

define i64 @"tracepoint:syscalls:sys_enter_open"(i8*) local_unnamed_addr section "s_tracepoint:syscalls:sys_enter_open_1" {
entry:
  %"@_val" = alloca i64, align 8
  %_tracepoint_syscalls_sys_enter_open.filename = alloca i64, align 8
  %str = alloca [64 x i8], align 1
  %"@_key" = alloca [64 x i8], align 1
  %1 = getelementptr inbounds [64 x i8], [64 x i8]* %"@_key", i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %2 = getelementptr inbounds [64 x i8], [64 x i8]* %str, i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %2)
  call void @llvm.memset.p0i8.i64(i8* nonnull %2, i8 0, i64 64, i32 1, i1 false)
  %3 = ptrtoint i8* %0 to i64
  %4 = add i64 %3, 16
  %5 = inttoptr i64 %4 to i8*
  %6 = bitcast i64* %_tracepoint_syscalls_sys_enter_open.filename to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %6)
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i64* nonnull %_tracepoint_syscalls_sys_enter_open.filename, i64 8, i8* %5)
  %7 = load i64, i64* %_tracepoint_syscalls_sys_enter_open.filename, align 8
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %6)
  %probe_read_str = call i64 inttoptr (i64 45 to i64 (i8*, i64, i8*)*)([64 x i8]* nonnull %str, i64 64, i64 %7)
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* nonnull %1, i8* nonnull %2, i64 64, i32 1, i1 false)
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i8*, i64*)*)(i64 %pseudo, [64 x i8]* nonnull %"@_key")
  %map_lookup_cond = icmp eq i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_merge, label %lookup_success

lookup_success:                                   ; preds = %entry
  %8 = load i64, i8* %lookup_elem, align 8
  %phitmp = add i64 %8, 1
  br label %lookup_merge

lookup_merge:                                     ; preds = %entry, %lookup_success
  %lookup_elem_val.0 = phi i64 [ %phitmp, %lookup_success ], [ 1, %entry ]
  %9 = bitcast i64* %"@_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %9)
  store i64 %lookup_elem_val.0, i64* %"@_val", align 8
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i8*, i64*, [64 x i8]*, i64)*)(i64 %pseudo1, [64 x i8]* nonnull %"@_key", i64* nonnull %"@_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %9)
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
  %3 = ptrtoint i8* %0 to i64
  %4 = add i64 %3, 24
  %5 = inttoptr i64 %4 to i8*
  %6 = bitcast i64* %_tracepoint_syscalls_sys_enter_openat.filename to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %6)
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i64* nonnull %_tracepoint_syscalls_sys_enter_openat.filename, i64 8, i8* %5)
  %7 = load i64, i64* %_tracepoint_syscalls_sys_enter_openat.filename, align 8
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %6)
  %probe_read_str = call i64 inttoptr (i64 45 to i64 (i8*, i64, i8*)*)([64 x i8]* nonnull %str, i64 64, i64 %7)
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* nonnull %1, i8* nonnull %2, i64 64, i32 1, i1 false)
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i8*, i64*)*)(i64 %pseudo, [64 x i8]* nonnull %"@_key")
  %map_lookup_cond = icmp eq i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_merge, label %lookup_success

lookup_success:                                   ; preds = %entry
  %8 = load i64, i8* %lookup_elem, align 8
  %phitmp = add i64 %8, 1
  br label %lookup_merge

lookup_merge:                                     ; preds = %entry, %lookup_success
  %lookup_elem_val.0 = phi i64 [ %phitmp, %lookup_success ], [ 1, %entry ]
  %9 = bitcast i64* %"@_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %9)
  store i64 %lookup_elem_val.0, i64* %"@_val", align 8
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i8*, i64*, [64 x i8]*, i64)*)(i64 %pseudo1, [64 x i8]* nonnull %"@_key", i64* nonnull %"@_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %9)
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

