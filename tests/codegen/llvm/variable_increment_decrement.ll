; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%printf_t.2 = type { i64, i64 }
%printf_t.1 = type { i64, i64 }
%printf_t.0 = type { i64, i64 }
%printf_t = type { i64, i64 }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @BEGIN(i8* %0) section "s_BEGIN_1" {
entry:
  %printf_args7 = alloca %printf_t.2, align 8
  %printf_args4 = alloca %printf_t.1, align 8
  %printf_args1 = alloca %printf_t.0, align 8
  %printf_args = alloca %printf_t, align 8
  %"$x" = alloca i64, align 8
  %1 = bitcast i64* %"$x" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 0, i64* %"$x", align 8
  store i64 10, i64* %"$x", align 8
  %2 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %2)
  %3 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %3, i8 0, i64 16, i1 false)
  %4 = getelementptr %printf_t, %printf_t* %printf_args, i32 0, i32 0
  store i64 0, i64* %4, align 8
  %5 = load i64, i64* %"$x", align 8
  %6 = add i64 %5, 1
  store i64 %6, i64* %"$x", align 8
  %7 = getelementptr %printf_t, %printf_t* %printf_args, i32 0, i32 1
  store i64 %5, i64* %7, align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %printf_t*, i64)*)(i8* %0, i64 %pseudo, i64 4294967295, %printf_t* %printf_args, i64 16)
  %8 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %8)
  %9 = bitcast %printf_t.0* %printf_args1 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %9)
  %10 = bitcast %printf_t.0* %printf_args1 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %10, i8 0, i64 16, i1 false)
  %11 = getelementptr %printf_t.0, %printf_t.0* %printf_args1, i32 0, i32 0
  store i64 1, i64* %11, align 8
  %12 = load i64, i64* %"$x", align 8
  %13 = add i64 %12, 1
  store i64 %13, i64* %"$x", align 8
  %14 = getelementptr %printf_t.0, %printf_t.0* %printf_args1, i32 0, i32 1
  store i64 %13, i64* %14, align 8
  %pseudo2 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %perf_event_output3 = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %printf_t.0*, i64)*)(i8* %0, i64 %pseudo2, i64 4294967295, %printf_t.0* %printf_args1, i64 16)
  %15 = bitcast %printf_t.0* %printf_args1 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %15)
  %16 = bitcast %printf_t.1* %printf_args4 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %16)
  %17 = bitcast %printf_t.1* %printf_args4 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %17, i8 0, i64 16, i1 false)
  %18 = getelementptr %printf_t.1, %printf_t.1* %printf_args4, i32 0, i32 0
  store i64 2, i64* %18, align 8
  %19 = load i64, i64* %"$x", align 8
  %20 = sub i64 %19, 1
  store i64 %20, i64* %"$x", align 8
  %21 = getelementptr %printf_t.1, %printf_t.1* %printf_args4, i32 0, i32 1
  store i64 %19, i64* %21, align 8
  %pseudo5 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %perf_event_output6 = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %printf_t.1*, i64)*)(i8* %0, i64 %pseudo5, i64 4294967295, %printf_t.1* %printf_args4, i64 16)
  %22 = bitcast %printf_t.1* %printf_args4 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %22)
  %23 = bitcast %printf_t.2* %printf_args7 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %23)
  %24 = bitcast %printf_t.2* %printf_args7 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %24, i8 0, i64 16, i1 false)
  %25 = getelementptr %printf_t.2, %printf_t.2* %printf_args7, i32 0, i32 0
  store i64 3, i64* %25, align 8
  %26 = load i64, i64* %"$x", align 8
  %27 = sub i64 %26, 1
  store i64 %27, i64* %"$x", align 8
  %28 = getelementptr %printf_t.2, %printf_t.2* %printf_args7, i32 0, i32 1
  store i64 %27, i64* %28, align 8
  %pseudo8 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %perf_event_output9 = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %printf_t.2*, i64)*)(i8* %0, i64 %pseudo8, i64 4294967295, %printf_t.2* %printf_args7, i64 16)
  %29 = bitcast %printf_t.2* %printf_args7 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %29)
  ret i64 0
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn writeonly
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }
attributes #2 = { argmemonly nofree nosync nounwind willreturn writeonly }
