; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

%printf_t = type { i64, i64 }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

define i64 @"kprobe:f"(i8*) section "s_kprobe:f_1" {
entry:
  %printf_args = alloca %printf_t
  %"$s" = alloca i64
  %1 = bitcast i64* %"$s" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 0, i64* %"$s"
  %get_pid_tgid = call i64 inttoptr (i64 14 to i64 ()*)()
  %2 = lshr i64 %get_pid_tgid, 32
  %3 = icmp ugt i64 %2, 10000
  %4 = zext i1 %3 to i64
  %true_cond = icmp ne i64 %4, 0
  br i1 %true_cond, label %if_body, label %if_end

if_body:                                          ; preds = %entry
  %5 = bitcast i64* %"$s" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %5)
  store i64 10, i64* %"$s"
  br label %if_end

if_end:                                           ; preds = %if_body, %entry
  %6 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %6)
  %7 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %7, i8 0, i64 16, i1 false)
  %8 = getelementptr %printf_t, %printf_t* %printf_args, i32 0, i32 0
  store i64 0, i64* %8
  %9 = load i64, i64* %"$s"
  %10 = getelementptr %printf_t, %printf_t* %printf_args, i32 0, i32 1
  store i64 %9, i64* %10
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %get_cpu_id = call i64 inttoptr (i64 8 to i64 ()*)()
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %printf_t*, i64)*)(i8* %0, i64 %pseudo, i64 %get_cpu_id, %printf_t* %printf_args, i64 16)
  %11 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %11)
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
