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
  store i64 10, i64* %"$x"
  %2 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %2)
  %3 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %3, i8 0, i64 16, i1 false)
  %4 = getelementptr %printf_t, %printf_t* %printf_args, i32 0, i32 0
  store i64 0, i64* %4
  %5 = load i64, i64* %"$x"
  %6 = add i64 %5, 1
  store i64 %6, i64* %"$x"
  %7 = getelementptr %printf_t, %printf_t* %printf_args, i32 0, i32 1
  store i64 %5, i64* %7
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %printf_t*, i64)*)(i8* %0, i64 %pseudo, i64 4294967295, %printf_t* %printf_args, i64 16)
  %8 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %8)
  %9 = bitcast %printf_t.0* %printf_args1 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %9)
  %10 = bitcast %printf_t.0* %printf_args1 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %10, i8 0, i64 16, i1 false)
  %11 = getelementptr %printf_t.0, %printf_t.0* %printf_args1, i32 0, i32 0
  store i64 1, i64* %11
  %12 = load i64, i64* %"$x"
  %13 = add i64 %12, 1
  store i64 %13, i64* %"$x"
  %14 = getelementptr %printf_t.0, %printf_t.0* %printf_args1, i32 0, i32 1
  store i64 %13, i64* %14
  %pseudo2 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %perf_event_output3 = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %printf_t.0*, i64)*)(i8* %0, i64 %pseudo2, i64 4294967295, %printf_t.0* %printf_args1, i64 16)
  %15 = bitcast %printf_t.0* %printf_args1 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %15)
  %16 = bitcast %printf_t.1* %printf_args4 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %16)
  %17 = bitcast %printf_t.1* %printf_args4 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %17, i8 0, i64 16, i1 false)
  %18 = getelementptr %printf_t.1, %printf_t.1* %printf_args4, i32 0, i32 0
  store i64 2, i64* %18
  %19 = load i64, i64* %"$x"
  %20 = sub i64 %19, 1
  store i64 %20, i64* %"$x"
  %21 = getelementptr %printf_t.1, %printf_t.1* %printf_args4, i32 0, i32 1
  store i64 %19, i64* %21
  %pseudo5 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %perf_event_output6 = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %printf_t.1*, i64)*)(i8* %0, i64 %pseudo5, i64 4294967295, %printf_t.1* %printf_args4, i64 16)
  %22 = bitcast %printf_t.1* %printf_args4 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %22)
  %23 = bitcast %printf_t.2* %printf_args7 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %23)
  %24 = bitcast %printf_t.2* %printf_args7 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %24, i8 0, i64 16, i1 false)
  %25 = getelementptr %printf_t.2, %printf_t.2* %printf_args7, i32 0, i32 0
  store i64 3, i64* %25
  %26 = load i64, i64* %"$x"
  %27 = sub i64 %26, 1
  store i64 %27, i64* %"$x"
  %28 = getelementptr %printf_t.2, %printf_t.2* %printf_args7, i32 0, i32 1
  store i64 %27, i64* %28
  %pseudo8 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %perf_event_output9 = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %printf_t.2*, i64)*)(i8* %0, i64 %pseudo8, i64 4294967295, %printf_t.2* %printf_args7, i64 16)
  %29 = bitcast %printf_t.2* %printf_args7 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %29)
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
