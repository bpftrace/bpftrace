; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

%helper_error_t = type <{ i64, i64, i32, i8 }>

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

define i64 @BEGIN(i8*) section "s_BEGIN_1" {
entry:
  %"@y_key" = alloca i64
  %str = alloca [1 x i8]
  %helper_error_t = alloca %helper_error_t
  %lookup_str_key = alloca i32
  %strlen = alloca i64
  %"@x_key" = alloca i64
  %"@x_val" = alloca i64
  %1 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 0, i64* %"@x_val"
  %2 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %2)
  store i64 0, i64* %"@x_key"
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo, i64* %"@x_key", i64* %"@x_val", i64 0)
  %3 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %3)
  %4 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %4)
  %5 = bitcast i64* %strlen to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %5)
  store i64 64, i64* %strlen
  %6 = bitcast i32* %lookup_str_key to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %6)
  store i32 0, i32* %lookup_str_key
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 4)
  %lookup_str_map = call [64 x i8]* inttoptr (i64 1 to [64 x i8]* (i64, i32*)*)(i64 %pseudo1, i32* %lookup_str_key)
  %7 = bitcast i32* %lookup_str_key to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %7)
  %8 = sext [64 x i8]* %lookup_str_map to i32
  %9 = icmp ne i32 %8, 0
  br i1 %9, label %helper_merge, label %helper_failure

helper_failure:                                   ; preds = %entry
  %10 = bitcast %helper_error_t* %helper_error_t to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %10)
  %11 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 0
  store i64 30006, i64* %11
  %12 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 1
  store i64 0, i64* %12
  %13 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 2
  store i32 %8, i32* %13
  %14 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 3
  store i8 1, i8* %14
  %pseudo2 = call i64 @llvm.bpf.pseudo(i64 1, i64 3)
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %helper_error_t*, i64)*)(i8* %0, i64 %pseudo2, i64 4294967295, %helper_error_t* %helper_error_t, i64 21)
  %15 = bitcast %helper_error_t* %helper_error_t to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %15)
  ret i64 0

helper_merge:                                     ; preds = %entry
  %16 = bitcast [64 x i8]* %lookup_str_map to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %16, i8 0, i64 64, i1 false)
  %17 = bitcast [1 x i8]* %str to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %17)
  %18 = bitcast [1 x i8]* %str to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %18, i8 0, i64 1, i1 false)
  store [1 x i8] zeroinitializer, [1 x i8]* %str
  %19 = load i64, i64* %strlen
  %probe_read_str = call i64 inttoptr (i64 45 to i64 ([64 x i8]*, i32, [1 x i8]*)*)([64 x i8]* %lookup_str_map, i64 %19, [1 x i8]* %str)
  %20 = bitcast i64* %strlen to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %20)
  %21 = bitcast [1 x i8]* %str to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %21)
  %22 = bitcast i64* %"@y_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %22)
  store i64 0, i64* %"@y_key"
  %pseudo3 = call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  %update_elem4 = call i64 inttoptr (i64 2 to i64 (i64, i64*, [64 x i8]*, i64)*)(i64 %pseudo3, i64* %"@y_key", [64 x i8]* %lookup_str_map, i64 0)
  %23 = bitcast i64* %"@y_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %23)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
