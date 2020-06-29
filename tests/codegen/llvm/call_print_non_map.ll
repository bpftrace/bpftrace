; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

%print_integer_8_t = type <{ i64, i64, [8 x i8] }>

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"kprobe:f"(i8*) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %print_integer_8_t = alloca %print_integer_8_t, align 8
  %1 = bitcast %print_integer_8_t* %print_integer_8_t to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %2 = getelementptr inbounds %print_integer_8_t, %print_integer_8_t* %print_integer_8_t, i64 0, i32 0
  store i64 30007, i64* %2, align 8
  %3 = getelementptr inbounds %print_integer_8_t, %print_integer_8_t* %print_integer_8_t, i64 0, i32 1
  %4 = getelementptr inbounds %print_integer_8_t, %print_integer_8_t* %print_integer_8_t, i64 0, i32 2
  store i64 0, i64* %3, align 8
  store i64 3, [8 x i8]* %4, align 8
  %pseudo = tail call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %get_cpu_id = tail call i64 inttoptr (i64 8 to i64 ()*)()
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %print_integer_8_t*, i64)*)(i8* %0, i64 %pseudo, i64 %get_cpu_id, %print_integer_8_t* nonnull %print_integer_8_t, i64 24)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
