; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

%helper_error_t = type <{ i64, i64, i32, i8 }>

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

define i64 @"kprobe:f"(i8*) section "s_kprobe:f_1" {
entry:
  %"@x_key" = alloca i64
  %helper_error_t15 = alloca %helper_error_t
  %lookup_str_key10 = alloca i32
  %helper_error_t7 = alloca %helper_error_t
  %lookup_str_key2 = alloca i32
  %helper_error_t = alloca %helper_error_t
  %lookup_str_key = alloca i32
  %1 = bitcast i32* %lookup_str_key to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i32 2, i32* %lookup_str_key
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 3)
  %lookup_str_map = call [64 x i8]* inttoptr (i64 1 to [64 x i8]* (i64, i32*)*)(i64 %pseudo, i32* %lookup_str_key)
  %2 = bitcast i32* %lookup_str_key to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %2)
  %3 = sext [64 x i8]* %lookup_str_map to i32
  %4 = icmp ne i32 %3, 0
  br i1 %4, label %helper_merge, label %helper_failure

left:                                             ; preds = %helper_merge
  %5 = bitcast i32* %lookup_str_key2 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %5)
  store i32 0, i32* %lookup_str_key2
  %pseudo3 = call i64 @llvm.bpf.pseudo(i64 1, i64 3)
  %lookup_str_map4 = call [64 x i8]* inttoptr (i64 1 to [64 x i8]* (i64, i32*)*)(i64 %pseudo3, i32* %lookup_str_key2)
  %6 = bitcast i32* %lookup_str_key2 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %6)
  %7 = sext [64 x i8]* %lookup_str_map4 to i32
  %8 = icmp ne i32 %7, 0
  br i1 %8, label %helper_merge6, label %helper_failure5

right:                                            ; preds = %helper_merge
  %9 = bitcast i32* %lookup_str_key10 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %9)
  store i32 1, i32* %lookup_str_key10
  %pseudo11 = call i64 @llvm.bpf.pseudo(i64 1, i64 3)
  %lookup_str_map12 = call [64 x i8]* inttoptr (i64 1 to [64 x i8]* (i64, i32*)*)(i64 %pseudo11, i32* %lookup_str_key10)
  %10 = bitcast i32* %lookup_str_key10 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %10)
  %11 = sext [64 x i8]* %lookup_str_map12 to i32
  %12 = icmp ne i32 %11, 0
  br i1 %12, label %helper_merge14, label %helper_failure13

done:                                             ; preds = %helper_merge14, %helper_merge6
  %13 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %13)
  store i64 0, i64* %"@x_key"
  %pseudo18 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, [64 x i8]*, i64)*)(i64 %pseudo18, i64* %"@x_key", [64 x i8]* %lookup_str_map, i64 0)
  %14 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %14)
  %15 = bitcast [64 x i8]* %lookup_str_map to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %15)
  ret i64 0

helper_failure:                                   ; preds = %entry
  %16 = bitcast %helper_error_t* %helper_error_t to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %16)
  %17 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 0
  store i64 30006, i64* %17
  %18 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 1
  store i64 0, i64* %18
  %19 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 2
  store i32 %3, i32* %19
  %20 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 3
  store i8 1, i8* %20
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %helper_error_t*, i64)*)(i8* %0, i64 %pseudo1, i64 4294967295, %helper_error_t* %helper_error_t, i64 21)
  %21 = bitcast %helper_error_t* %helper_error_t to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %21)
  ret i64 0

helper_merge:                                     ; preds = %entry
  %22 = bitcast [64 x i8]* %lookup_str_map to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %22, i8 0, i64 64, i1 false)
  %get_pid_tgid = call i64 inttoptr (i64 14 to i64 ()*)()
  %23 = lshr i64 %get_pid_tgid, 32
  %24 = icmp ult i64 %23, 10000
  %25 = zext i1 %24 to i64
  %true_cond = icmp ne i64 %25, 0
  br i1 %true_cond, label %left, label %right

helper_failure5:                                  ; preds = %left
  %26 = bitcast %helper_error_t* %helper_error_t7 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %26)
  %27 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t7, i64 0, i32 0
  store i64 30006, i64* %27
  %28 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t7, i64 0, i32 1
  store i64 1, i64* %28
  %29 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t7, i64 0, i32 2
  store i32 %7, i32* %29
  %30 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t7, i64 0, i32 3
  store i8 1, i8* %30
  %pseudo8 = call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  %perf_event_output9 = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %helper_error_t*, i64)*)(i8* %0, i64 %pseudo8, i64 4294967295, %helper_error_t* %helper_error_t7, i64 21)
  %31 = bitcast %helper_error_t* %helper_error_t7 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %31)
  ret i64 0

helper_merge6:                                    ; preds = %left
  %32 = bitcast [64 x i8]* %lookup_str_map4 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %32, i8 0, i64 64, i1 false)
  store [3 x i8] c"lo\00", [64 x i8]* %lookup_str_map4
  %33 = bitcast [64 x i8]* %lookup_str_map to i8*
  %34 = bitcast [64 x i8]* %lookup_str_map4 to i8*
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* align 1 %33, i8* align 1 %34, i64 64, i1 false)
  br label %done

helper_failure13:                                 ; preds = %right
  %35 = bitcast %helper_error_t* %helper_error_t15 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %35)
  %36 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t15, i64 0, i32 0
  store i64 30006, i64* %36
  %37 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t15, i64 0, i32 1
  store i64 2, i64* %37
  %38 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t15, i64 0, i32 2
  store i32 %11, i32* %38
  %39 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t15, i64 0, i32 3
  store i8 1, i8* %39
  %pseudo16 = call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  %perf_event_output17 = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %helper_error_t*, i64)*)(i8* %0, i64 %pseudo16, i64 4294967295, %helper_error_t* %helper_error_t15, i64 21)
  %40 = bitcast %helper_error_t* %helper_error_t15 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %40)
  ret i64 0

helper_merge14:                                   ; preds = %right
  %41 = bitcast [64 x i8]* %lookup_str_map12 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %41, i8 0, i64 64, i1 false)
  store [3 x i8] c"hi\00", [64 x i8]* %lookup_str_map12
  %42 = bitcast [64 x i8]* %lookup_str_map to i8*
  %43 = bitcast [64 x i8]* %lookup_str_map12 to i8*
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* align 1 %42, i8* align 1 %43, i64 64, i1 false)
  br label %done
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
