; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

%printf_t.2 = type { i64, i64 }
%printf_t.1 = type { i64, i64 }
%printf_t.0 = type { i64, i64 }
%printf_t = type { i64, i64 }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

define i64 @BEGIN(i8*) section "s_BEGIN_1" {
entry:
  %printf_args7 = alloca %printf_t.2
  %printf_args4 = alloca %printf_t.1
  %printf_args1 = alloca %printf_t.0
  %printf_args = alloca %printf_t
  %"$x" = alloca i64
  %1 = bitcast i64* %"$x" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 0, i64* %"$x"
  %2 = bitcast i64* %"$x" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %2)
  store i64 10, i64* %"$x"
  %3 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %3)
  %4 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %4, i8 0, i64 16, i1 false)
  %5 = getelementptr %printf_t, %printf_t* %printf_args, i32 0, i32 0
  store i64 0, i64* %5
  %6 = load i64, i64* %"$x"
  %7 = add i64 %6, 1
  store i64 %7, i64* %"$x"
  %8 = getelementptr %printf_t, %printf_t* %printf_args, i32 0, i32 1
  store i64 %6, i64* %8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %printf_t*, i64)*)(i8* %0, i64 %pseudo, i64 4294967295, %printf_t* %printf_args, i64 16)
  %9 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %9)
  %10 = bitcast %printf_t.0* %printf_args1 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %10)
  %11 = bitcast %printf_t.0* %printf_args1 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %11, i8 0, i64 16, i1 false)
  %12 = getelementptr %printf_t.0, %printf_t.0* %printf_args1, i32 0, i32 0
  store i64 1, i64* %12
  %13 = load i64, i64* %"$x"
  %14 = add i64 %13, 1
  store i64 %14, i64* %"$x"
  %15 = getelementptr %printf_t.0, %printf_t.0* %printf_args1, i32 0, i32 1
  store i64 %14, i64* %15
  %pseudo2 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %perf_event_output3 = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %printf_t.0*, i64)*)(i8* %0, i64 %pseudo2, i64 4294967295, %printf_t.0* %printf_args1, i64 16)
  %16 = bitcast %printf_t.0* %printf_args1 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %16)
  %17 = bitcast %printf_t.1* %printf_args4 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %17)
  %18 = bitcast %printf_t.1* %printf_args4 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %18, i8 0, i64 16, i1 false)
  %19 = getelementptr %printf_t.1, %printf_t.1* %printf_args4, i32 0, i32 0
  store i64 2, i64* %19
  %20 = load i64, i64* %"$x"
  %21 = sub i64 %20, 1
  store i64 %21, i64* %"$x"
  %22 = getelementptr %printf_t.1, %printf_t.1* %printf_args4, i32 0, i32 1
  store i64 %20, i64* %22
  %pseudo5 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %perf_event_output6 = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %printf_t.1*, i64)*)(i8* %0, i64 %pseudo5, i64 4294967295, %printf_t.1* %printf_args4, i64 16)
  %23 = bitcast %printf_t.1* %printf_args4 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %23)
  %24 = bitcast %printf_t.2* %printf_args7 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %24)
  %25 = bitcast %printf_t.2* %printf_args7 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %25, i8 0, i64 16, i1 false)
  %26 = getelementptr %printf_t.2, %printf_t.2* %printf_args7, i32 0, i32 0
  store i64 3, i64* %26
  %27 = load i64, i64* %"$x"
  %28 = sub i64 %27, 1
  store i64 %28, i64* %"$x"
  %29 = getelementptr %printf_t.2, %printf_t.2* %printf_args7, i32 0, i32 1
  store i64 %28, i64* %29
  %pseudo8 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %perf_event_output9 = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %printf_t.2*, i64)*)(i8* %0, i64 %pseudo8, i64 4294967295, %printf_t.2* %printf_args7, i64 16)
  %30 = bitcast %printf_t.2* %printf_args7 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %30)
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
