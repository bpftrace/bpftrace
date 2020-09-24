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
  %2 = bitcast i8* %0 to i64*
  %3 = getelementptr i64, i64* %2, i64 14
  %arg0 = load volatile i64, i64* %3
  %4 = bitcast i64* %"$foo" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %4)
  store i64 %arg0, i64* %"$foo"
  %5 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %5)
  %6 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %6, i8 0, i64 24, i1 false)
  %7 = getelementptr %printf_t, %printf_t* %printf_args, i32 0, i32 0
  store i64 0, i64* %7
  %8 = load i64, i64* %"$foo"
  %9 = add i64 %8, 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %"struct Foo.c")
  %probe_read_kernel = call i64 inttoptr (i64 113 to i64 (i8*, i32, i64)*)(i8* %"struct Foo.c", i32 1, i64 %9)
  %10 = load i8, i8* %"struct Foo.c"
  %11 = sext i8 %10 to i64
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %"struct Foo.c")
  %12 = getelementptr %printf_t, %printf_t* %printf_args, i32 0, i32 1
  store i64 %11, i64* %12
  %13 = load i64, i64* %"$foo"
  %14 = add i64 %13, 8
  %15 = bitcast i64* %"struct Foo.l" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %15)
  %probe_read_kernel1 = call i64 inttoptr (i64 113 to i64 (i64*, i32, i64)*)(i64* %"struct Foo.l", i32 8, i64 %14)
  %16 = load i64, i64* %"struct Foo.l"
  %17 = bitcast i64* %"struct Foo.l" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %17)
  %18 = getelementptr %printf_t, %printf_t* %printf_args, i32 0, i32 2
  store i64 %16, i64* %18
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %get_cpu_id = call i64 inttoptr (i64 8 to i64 ()*)()
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %printf_t*, i64)*)(i8* %0, i64 %pseudo, i64 %get_cpu_id, %printf_t* %printf_args, i64 24)
  %19 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %19)
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
