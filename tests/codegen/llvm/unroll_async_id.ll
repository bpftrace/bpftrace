; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%printf_t.3 = type { i64 }
%printf_t.2 = type { i64 }
%printf_t.1 = type { i64 }
%printf_t.0 = type { i64 }
%printf_t = type { i64 }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @BEGIN(i8* %0) section "s_BEGIN_1" {
entry:
  %printf_args11 = alloca %printf_t.3, align 8
  %printf_args8 = alloca %printf_t.2, align 8
  %printf_args5 = alloca %printf_t.1, align 8
  %printf_args2 = alloca %printf_t.0, align 8
  %printf_args = alloca %printf_t, align 8
  %"@i_val" = alloca i64, align 8
  %"@i_key" = alloca i64, align 8
  %1 = bitcast i64* %"@i_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 0, i64* %"@i_key", align 8
  %2 = bitcast i64* %"@i_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %2)
  store i64 0, i64* %"@i_val", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo, i64* %"@i_key", i64* %"@i_val", i64 0)
  %3 = bitcast i64* %"@i_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %3)
  %4 = bitcast i64* %"@i_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %4)
  %5 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %5)
  %6 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %6, i8 0, i64 8, i1 false)
  %7 = getelementptr %printf_t, %printf_t* %printf_args, i32 0, i32 0
  store i64 0, i64* %7, align 8
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %printf_t*, i64)*)(i8* %0, i64 %pseudo1, i64 4294967295, %printf_t* %printf_args, i64 8)
  %8 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %8)
  %9 = bitcast %printf_t.0* %printf_args2 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %9)
  %10 = bitcast %printf_t.0* %printf_args2 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %10, i8 0, i64 8, i1 false)
  %11 = getelementptr %printf_t.0, %printf_t.0* %printf_args2, i32 0, i32 0
  store i64 0, i64* %11, align 8
  %pseudo3 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %perf_event_output4 = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %printf_t.0*, i64)*)(i8* %0, i64 %pseudo3, i64 4294967295, %printf_t.0* %printf_args2, i64 8)
  %12 = bitcast %printf_t.0* %printf_args2 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %12)
  %13 = bitcast %printf_t.1* %printf_args5 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %13)
  %14 = bitcast %printf_t.1* %printf_args5 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %14, i8 0, i64 8, i1 false)
  %15 = getelementptr %printf_t.1, %printf_t.1* %printf_args5, i32 0, i32 0
  store i64 0, i64* %15, align 8
  %pseudo6 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %perf_event_output7 = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %printf_t.1*, i64)*)(i8* %0, i64 %pseudo6, i64 4294967295, %printf_t.1* %printf_args5, i64 8)
  %16 = bitcast %printf_t.1* %printf_args5 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %16)
  %17 = bitcast %printf_t.2* %printf_args8 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %17)
  %18 = bitcast %printf_t.2* %printf_args8 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %18, i8 0, i64 8, i1 false)
  %19 = getelementptr %printf_t.2, %printf_t.2* %printf_args8, i32 0, i32 0
  store i64 0, i64* %19, align 8
  %pseudo9 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %perf_event_output10 = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %printf_t.2*, i64)*)(i8* %0, i64 %pseudo9, i64 4294967295, %printf_t.2* %printf_args8, i64 8)
  %20 = bitcast %printf_t.2* %printf_args8 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %20)
  %21 = bitcast %printf_t.3* %printf_args11 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %21)
  %22 = bitcast %printf_t.3* %printf_args11 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %22, i8 0, i64 8, i1 false)
  %23 = getelementptr %printf_t.3, %printf_t.3* %printf_args11, i32 0, i32 0
  store i64 0, i64* %23, align 8
  %pseudo12 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %perf_event_output13 = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %printf_t.3*, i64)*)(i8* %0, i64 %pseudo12, i64 4294967295, %printf_t.3* %printf_args11, i64 8)
  %24 = bitcast %printf_t.3* %printf_args11 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %24)
  ret i64 0
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn writeonly
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }
attributes #2 = { argmemonly nofree nosync nounwind willreturn writeonly }
