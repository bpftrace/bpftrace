; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

%time_t = type <{ i64, i32 }>

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

define i64 @"kprobe:f"(i8*) section "s_kprobe:f_1" {
entry:
  %time_t = alloca %time_t
  %1 = bitcast %time_t* %time_t to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  %2 = getelementptr %time_t, %time_t* %time_t, i64 0, i32 0
  store i64 30004, i64* %2
  %3 = getelementptr %time_t, %time_t* %time_t, i64 0, i32 1
  store i32 0, i32* %3
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %get_cpu_id = call i64 inttoptr (i64 8 to i64 ()*)()
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %time_t*, i64)*)(i8* %0, i64 %pseudo, i64 %get_cpu_id, %time_t* %time_t, i64 12)
  %4 = bitcast %time_t* %time_t to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %4)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
