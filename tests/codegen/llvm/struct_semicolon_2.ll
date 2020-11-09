; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

%bpf_pidns_info_t = type { i32, i32 }
%printf_t = type { i64, i64 }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

define i64 @"kprobe:f"(i8*) section "s_kprobe:f_1" {
entry:
  %bpf_pidns_info = alloca %bpf_pidns_info_t
  %printf_args = alloca %printf_t
  %1 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  %2 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %2, i8 0, i64 16, i1 false)
  %3 = getelementptr %printf_t, %printf_t* %printf_args, i32 0, i32 0
  store i64 0, i64* %3
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %get_stackid = call i64 inttoptr (i64 27 to i64 (i8*, i64, i64)*)(i8* %0, i64 %pseudo, i64 256)
  %4 = bitcast %bpf_pidns_info_t* %bpf_pidns_info to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %4)
  %get_ns_current_pid_tgid = call i64 inttoptr (i64 120 to i64 (i64, i64, %bpf_pidns_info_t*, i32)*)(i64 0, i64 0, %bpf_pidns_info_t* %bpf_pidns_info, i32 8)
  %5 = getelementptr %bpf_pidns_info_t, %bpf_pidns_info_t* %bpf_pidns_info, i32 0, i32 0
  %6 = load i32, i32* %5
  %7 = zext i32 %6 to i64
  %8 = getelementptr %bpf_pidns_info_t, %bpf_pidns_info_t* %bpf_pidns_info, i32 0, i32 1
  %9 = load i32, i32* %8
  %10 = zext i32 %9 to i64
  %11 = bitcast %bpf_pidns_info_t* %bpf_pidns_info to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %11)
  %12 = shl i64 %10, 32
  %13 = or i64 %12, %7
  %14 = shl i64 %13, 32
  %15 = or i64 %get_stackid, %14
  %16 = getelementptr %printf_t, %printf_t* %printf_args, i32 0, i32 1
  store i64 %15, i64* %16
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  %get_cpu_id = call i64 inttoptr (i64 8 to i64 ()*)()
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %printf_t*, i64)*)(i8* %0, i64 %pseudo1, i64 %get_cpu_id, %printf_t* %printf_args, i64 16)
  %17 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %17)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i1) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
