; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

%print_tuple_72_t = type <{ i64, i64, [72 x i8] }>
%helper_error_t = type <{ i64, i64, i32, i8 }>
%"int64_string[64]__tuple_t" = type <{ i64, [64 x i8] }>

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

define i64 @"kprobe:f"(i8*) section "s_kprobe:f_1" {
entry:
  %print_tuple_72_t = alloca %print_tuple_72_t
  %helper_error_t = alloca %helper_error_t
  %lookup_str_key = alloca i32
  %tuple = alloca %"int64_string[64]__tuple_t"
  %1 = bitcast %"int64_string[64]__tuple_t"* %tuple to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  %2 = getelementptr %"int64_string[64]__tuple_t", %"int64_string[64]__tuple_t"* %tuple, i32 0, i32 0
  store i64 1, i64* %2
  %3 = bitcast i32* %lookup_str_key to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %3)
  store i32 0, i32* %lookup_str_key
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  %lookup_str_map = call [64 x i8]* inttoptr (i64 1 to [64 x i8]* (i64, i32*)*)(i64 %pseudo, i32* %lookup_str_key)
  %4 = bitcast i32* %lookup_str_key to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %4)
  %5 = sext [64 x i8]* %lookup_str_map to i32
  %6 = icmp ne i32 %5, 0
  br i1 %6, label %helper_merge, label %helper_failure

helper_failure:                                   ; preds = %entry
  %7 = bitcast %helper_error_t* %helper_error_t to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %7)
  %8 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 0
  store i64 30006, i64* %8
  %9 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 1
  store i64 0, i64* %9
  %10 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 2
  store i32 %5, i32* %10
  %11 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 3
  store i8 1, i8* %11
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %helper_error_t*, i64)*)(i8* %0, i64 %pseudo1, i64 4294967295, %helper_error_t* %helper_error_t, i64 21)
  %12 = bitcast %helper_error_t* %helper_error_t to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %12)
  ret i64 0

helper_merge:                                     ; preds = %entry
  %13 = bitcast [64 x i8]* %lookup_str_map to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %13, i8 0, i64 64, i1 false)
  store [4 x i8] c"abc\00", [64 x i8]* %lookup_str_map
  %14 = getelementptr %"int64_string[64]__tuple_t", %"int64_string[64]__tuple_t"* %tuple, i32 0, i32 1
  %15 = bitcast [64 x i8]* %14 to i8*
  %16 = bitcast [64 x i8]* %lookup_str_map to i8*
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* align 1 %15, i8* align 1 %16, i64 64, i1 false)
  %17 = bitcast %print_tuple_72_t* %print_tuple_72_t to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %17)
  %18 = getelementptr %print_tuple_72_t, %print_tuple_72_t* %print_tuple_72_t, i64 0, i32 0
  store i64 30007, i64* %18
  %19 = getelementptr %print_tuple_72_t, %print_tuple_72_t* %print_tuple_72_t, i64 0, i32 1
  store i64 0, i64* %19
  %20 = getelementptr %print_tuple_72_t, %print_tuple_72_t* %print_tuple_72_t, i32 0, i32 2
  %21 = bitcast [72 x i8]* %20 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %21, i8 0, i64 72, i1 false)
  %22 = bitcast [72 x i8]* %20 to i8*
  %23 = bitcast %"int64_string[64]__tuple_t"* %tuple to i8*
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* align 1 %22, i8* align 1 %23, i64 72, i1 false)
  %pseudo2 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %perf_event_output3 = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %print_tuple_72_t*, i64)*)(i8* %0, i64 %pseudo2, i64 4294967295, %print_tuple_72_t* %print_tuple_72_t, i64 88)
  %24 = bitcast %print_tuple_72_t* %print_tuple_72_t to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %24)
  %25 = bitcast %"int64_string[64]__tuple_t"* %tuple to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %25)
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
