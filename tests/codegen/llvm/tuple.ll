; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

%helper_error_t = type <{ i64, i64, i32, i8 }>
%"int64_int64_string[64]__tuple_t" = type <{ i64, i64, [64 x i8] }>

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

define i64 @"kprobe:f"(i8*) section "s_kprobe:f_1" {
entry:
  %"@t_key" = alloca i64
  %helper_error_t = alloca %helper_error_t
  %lookup_str_key = alloca i32
  %tuple = alloca %"int64_int64_string[64]__tuple_t"
  %1 = bitcast %"int64_int64_string[64]__tuple_t"* %tuple to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  %2 = getelementptr %"int64_int64_string[64]__tuple_t", %"int64_int64_string[64]__tuple_t"* %tuple, i32 0, i32 0
  store i64 1, i64* %2
  %3 = getelementptr %"int64_int64_string[64]__tuple_t", %"int64_int64_string[64]__tuple_t"* %tuple, i32 0, i32 1
  store i64 2, i64* %3
  %4 = bitcast i32* %lookup_str_key to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %4)
  store i32 0, i32* %lookup_str_key
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 3)
  %lookup_str_map = call [64 x i8]* inttoptr (i64 1 to [64 x i8]* (i64, i32*)*)(i64 %pseudo, i32* %lookup_str_key)
  %5 = bitcast i32* %lookup_str_key to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %5)
  %6 = sext [64 x i8]* %lookup_str_map to i32
  %7 = icmp ne i32 %6, 0
  br i1 %7, label %helper_merge, label %helper_failure

helper_failure:                                   ; preds = %entry
  %8 = bitcast %helper_error_t* %helper_error_t to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %8)
  %9 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 0
  store i64 30006, i64* %9
  %10 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 1
  store i64 0, i64* %10
  %11 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 2
  store i32 %6, i32* %11
  %12 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 3
  store i8 1, i8* %12
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %helper_error_t*, i64)*)(i8* %0, i64 %pseudo1, i64 4294967295, %helper_error_t* %helper_error_t, i64 21)
  %13 = bitcast %helper_error_t* %helper_error_t to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %13)
  ret i64 0

helper_merge:                                     ; preds = %entry
  %14 = bitcast [64 x i8]* %lookup_str_map to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %14, i8 0, i64 64, i1 false)
  store [4 x i8] c"str\00", [64 x i8]* %lookup_str_map
  %15 = getelementptr %"int64_int64_string[64]__tuple_t", %"int64_int64_string[64]__tuple_t"* %tuple, i32 0, i32 2
  %16 = bitcast [64 x i8]* %15 to i8*
  %17 = bitcast [64 x i8]* %lookup_str_map to i8*
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* align 1 %16, i8* align 1 %17, i64 64, i1 false)
  %18 = bitcast i64* %"@t_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %18)
  store i64 0, i64* %"@t_key"
  %pseudo2 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, %"int64_int64_string[64]__tuple_t"*, i64)*)(i64 %pseudo2, i64* %"@t_key", %"int64_int64_string[64]__tuple_t"* %tuple, i64 0)
  %19 = bitcast i64* %"@t_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %19)
  %20 = bitcast %"int64_int64_string[64]__tuple_t"* %tuple to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %20)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i1) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.memcpy.p0i8.p0i8.i64(i8* nocapture writeonly, i8* nocapture readonly, i64, i1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
