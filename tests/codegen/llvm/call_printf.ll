; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

%printf_t = type { i64, i64, i64 }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

define i64 @"kprobe:f"(i8*) section "s_kprobe:f_1" {
entry:
  %"struct Foo.l" = alloca i64
  %"struct Foo.c" = alloca i8
  %printf_args = alloca %printf_t
  %"$foo" = alloca i64
  %1 = bitcast i64* %"$foo" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 0, i64* %"$foo"
  %2 = bitcast i64* %"$foo" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %2)
  store i64 0, i64* %"$foo"
  %3 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %3)
  %4 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %4, i8 0, i64 24, i1 false)
  %5 = getelementptr %printf_t, %printf_t* %printf_args, i32 0, i32 0
  store i64 0, i64* %5
  %6 = load i64, i64* %"$foo"
  %7 = add i64 %6, 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %"struct Foo.c")
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i32, i64)*)(i8* %"struct Foo.c", i32 1, i64 %7)
  %8 = load i8, i8* %"struct Foo.c"
  %9 = sext i8 %8 to i64
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %"struct Foo.c")
  %10 = getelementptr %printf_t, %printf_t* %printf_args, i32 0, i32 1
  store i64 %9, i64* %10
  %11 = load i64, i64* %"$foo"
  %12 = add i64 %11, 8
  %13 = bitcast i64* %"struct Foo.l" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %13)
  %probe_read1 = call i64 inttoptr (i64 4 to i64 (i64*, i32, i64)*)(i64* %"struct Foo.l", i32 8, i64 %12)
  %14 = load i64, i64* %"struct Foo.l"
  %15 = bitcast i64* %"struct Foo.l" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %15)
  %16 = getelementptr %printf_t, %printf_t* %printf_args, i32 0, i32 2
  store i64 %14, i64* %16
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %get_cpu_id = call i64 inttoptr (i64 8 to i64 ()*)()
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %printf_t*, i64)*)(i8* %0, i64 %pseudo, i64 %get_cpu_id, %printf_t* %printf_args, i64 24)
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
