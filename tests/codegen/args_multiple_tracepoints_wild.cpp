#include "common.h"

using ::testing::Return;
using ::testing::_;

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, args_multiple_tracepoints_wild)
{
  std::set<std::string> wildcard_matches = {
    "sys_enter_recvfrom",
    "sys_enter_recvmmsg",
    "sys_enter_recvmsg",
  };
  MockBPFtrace bpftrace;

  ON_CALL(bpftrace, find_wildcard_matches(_, _, _))
    .WillByDefault(Return(wildcard_matches));
  ON_CALL(bpftrace, add_probe(_))
    .WillByDefault(Return(0));

  std::string sys_enter_recvfrom_input =
    "name: sys_enter_recvfrom\n"
    "ID: 1270\n"
    "format:\n"
    "	field:unsigned short common_type;	offset:0;	size:2;	signed:0;\n"
    "	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;\n"
    "	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;\n"
    "	field:int common_pid;	offset:4;	size:4;	signed:1;\n"
    "\n"
    "	field:int __syscall_nr;	offset:8;	size:4;	signed:1;\n"
    "	field:long fd;	offset:16;	size:8;	signed:0;\n"
    "	field:void * ubuf;	offset:24;	size:8;	signed:0;\n"
    "	field:unsigned long size;	offset:32;	size:8;	signed:0;\n"
    "	field:unsigned long flags;	offset:40;	size:8;	signed:0;\n"
    "	field:void * addr;	offset:48;	size:8;	signed:0;\n"
    "	field:int * addr_len;	offset:56;	size:8;	signed:0;\n"
    "\n"
    "print fmt: \"fd: 0x%08lx, ubuf: 0x%08lx, size: 0x%08lx, flags: 0x%08lx, addr: 0x%08lx, addr_len: 0x%08lx\", ((unsigned long)(REC->fd)), ((unsigned long)(REC->ubuf)), ((unsigned long)(REC->size)), ((unsigned long)(REC->flags)), ((unsigned long)(REC->addr)), ((unsigned long)(REC->addr_len))\n";
  std::istringstream sys_enter_recvfrom_format_file(sys_enter_recvfrom_input);
  std::string sys_enter_recvfrom_struct = MockTracepointFormatParser::get_tracepoint_struct_public(sys_enter_recvfrom_format_file, "syscalls", "sys_enter_recvfrom");

  std::string sys_enter_recvmmsg_input =
    "name: sys_enter_recvmmsg\n"
    "ID: 1256\n"
    "format:\n"
    "	field:unsigned short common_type;	offset:0;	size:2;	signed:0;\n"
    "	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;\n"
    "	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;\n"
    "	field:int common_pid;	offset:4;	size:4;	signed:1;\n"
    "\n"
    "	field:int __syscall_nr;	offset:8;	size:4;	signed:1;\n"
    "	field:long fd;	offset:16;	size:8;	signed:0;\n"
    "	field:void * mmsg;	offset:24;	size:8;	signed:0;\n"
    "	field:unsigned long vlen;	offset:32;	size:8;	signed:0;\n"
    "	field:unsigned long flags;	offset:40;	size:8;	signed:0;\n"
    "	field:void * timeout;	offset:48;	size:8;	signed:0;\n"
    "\n"
    "print fmt: \"fd: 0x%08lx, mmsg: 0x%08lx, vlen: 0x%08lx, flags: 0x%08lx, timeout: 0x%08lx\", ((unsigned long)(REC->fd)), ((unsigned long)(REC->mmsg)), ((unsigned long)(REC->vlen)), ((unsigned long)(REC->flags)), ((unsigned long)(REC->timeout))\n";
  std::istringstream sys_enter_recvmmsg_format_file(sys_enter_recvmmsg_input);
  std::string sys_enter_recvmmsg_struct = MockTracepointFormatParser::get_tracepoint_struct_public(sys_enter_recvmmsg_format_file, "syscalls", "sys_enter_recvmmsg");

  std::string sys_enter_recvmsg_input =
    "name: sys_enter_recvmsg\n"
    "ID: 1258\n"
    "format:\n"
    "	field:unsigned short common_type;	offset:0;	size:2;	signed:0;\n"
    "	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;\n"
    "	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;\n"
    "	field:int common_pid;	offset:4;	size:4;	signed:1;\n"
    "\n"
    "	field:int __syscall_nr;	offset:8;	size:4;	signed:1;\n"
    "	field:long fd;	offset:16;	size:8;	signed:0;\n"
    "	field:void * msg;	offset:24;	size:8;	signed:0;\n"
    "	field:unsigned long flags;	offset:32;	size:8;	signed:0;\n"
    "\n"
    "print fmt: \"fd: 0x%08lx, msg: 0x%08lx, flags: 0x%08lx\", ((unsigned long)(REC->fd)), ((unsigned long)(REC->msg)), ((unsigned long)(REC->flags))\n";
  std::istringstream sys_enter_recvmsg_format_file(sys_enter_recvmsg_input);
  std::string sys_enter_recvmsg_struct = MockTracepointFormatParser::get_tracepoint_struct_public(sys_enter_recvmsg_format_file, "syscalls", "sys_enter_recvmsg");

  test(bpftrace,
      sys_enter_recvfrom_struct + sys_enter_recvmmsg_struct + sys_enter_recvmsg_struct +
      "tracepoint:syscalls:sys_enter_recv* { @[args->flags] = count(); }",

#if LLVM_VERSION_MAJOR > 6
R"EXPECTED(; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"tracepoint:syscalls:sys_enter_recvfrom"(i8*) local_unnamed_addr section "s_tracepoint:syscalls:sys_enter_recvfrom_1" {
entry:
  %"@_val" = alloca i64, align 8
  %"struct _tracepoint_syscalls_sys_enter_recvfrom.flags" = alloca i64, align 8
  %"@_key" = alloca [8 x i8], align 8
  %1 = getelementptr inbounds [8 x i8], [8 x i8]* %"@_key", i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %2 = add i8* %0, i64 40
  %3 = bitcast i64* %"struct _tracepoint_syscalls_sys_enter_recvfrom.flags" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %3)
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i64* nonnull %"struct _tracepoint_syscalls_sys_enter_recvfrom.flags", i64 8, i8* %2)
  %4 = load i64, i64* %"struct _tracepoint_syscalls_sys_enter_recvfrom.flags", align 8
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
  %"struct _tracepoint_syscalls_sys_enter_recvmmsg.flags" = alloca i64, align 8
  %"@_key" = alloca [8 x i8], align 8
  %1 = getelementptr inbounds [8 x i8], [8 x i8]* %"@_key", i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %2 = add i8* %0, i64 40
  %3 = bitcast i64* %"struct _tracepoint_syscalls_sys_enter_recvmmsg.flags" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %3)
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i64* nonnull %"struct _tracepoint_syscalls_sys_enter_recvmmsg.flags", i64 8, i8* %2)
  %4 = load i64, i64* %"struct _tracepoint_syscalls_sys_enter_recvmmsg.flags", align 8
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
  %"struct _tracepoint_syscalls_sys_enter_recvmsg.flags" = alloca i64, align 8
  %"@_key" = alloca [8 x i8], align 8
  %1 = getelementptr inbounds [8 x i8], [8 x i8]* %"@_key", i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %2 = add i8* %0, i64 32
  %3 = bitcast i64* %"struct _tracepoint_syscalls_sys_enter_recvmsg.flags" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %3)
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i64* nonnull %"struct _tracepoint_syscalls_sys_enter_recvmsg.flags", i64 8, i8* %2)
  %4 = load i64, i64* %"struct _tracepoint_syscalls_sys_enter_recvmsg.flags", align 8
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
#else
R"EXPECTED(; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"tracepoint:syscalls:sys_enter_recvfrom"(i8*) local_unnamed_addr section "s_tracepoint:syscalls:sys_enter_recvfrom_1" {
entry:
  %"@_val" = alloca i64, align 8
  %"struct _tracepoint_syscalls_sys_enter_recvfrom.flags" = alloca i64, align 8
  %"@_key" = alloca [8 x i8], align 8
  %1 = getelementptr inbounds [8 x i8], [8 x i8]* %"@_key", i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %2 = add i8* %0, i64 40
  %3 = bitcast i64* %"struct _tracepoint_syscalls_sys_enter_recvfrom.flags" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %3)
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i64* nonnull %"struct _tracepoint_syscalls_sys_enter_recvfrom.flags", i64 8, i8* %2)
  %4 = load i64, i64* %"struct _tracepoint_syscalls_sys_enter_recvfrom.flags", align 8
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
  %"struct _tracepoint_syscalls_sys_enter_recvmmsg.flags" = alloca i64, align 8
  %"@_key" = alloca [8 x i8], align 8
  %1 = getelementptr inbounds [8 x i8], [8 x i8]* %"@_key", i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %2 = add i8* %0, i64 40
  %3 = bitcast i64* %"struct _tracepoint_syscalls_sys_enter_recvmmsg.flags" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %3)
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i64* nonnull %"struct _tracepoint_syscalls_sys_enter_recvmmsg.flags", i64 8, i8* %2)
  %4 = load i64, i64* %"struct _tracepoint_syscalls_sys_enter_recvmmsg.flags", align 8
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
  %"struct _tracepoint_syscalls_sys_enter_recvmsg.flags" = alloca i64, align 8
  %"@_key" = alloca [8 x i8], align 8
  %1 = getelementptr inbounds [8 x i8], [8 x i8]* %"@_key", i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %2 = add i8* %0, i64 32
  %3 = bitcast i64* %"struct _tracepoint_syscalls_sys_enter_recvmsg.flags" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %3)
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i64* nonnull %"struct _tracepoint_syscalls_sys_enter_recvmsg.flags", i64 8, i8* %2)
  %4 = load i64, i64* %"struct _tracepoint_syscalls_sys_enter_recvmsg.flags", align 8
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
#endif
}

} // namespace codegen
} // namespace test
} // namespace bpftrace

