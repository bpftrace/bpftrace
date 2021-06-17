; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%helper_error_t = type <{ i64, i64, i32, i8 }>
%printf_t = type { i64 }
%printf_t.0 = type { i64 }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"kprobe:f"(i8* %0) section "s_kprobe:f_1" {
entry:
  %helper_error_t9 = alloca %helper_error_t, align 8
  %lookup_fmtstr_key5 = alloca i32, align 4
  %helper_error_t = alloca %helper_error_t, align 8
  %lookup_fmtstr_key = alloca i32, align 4
  br label %validate_map_lookup_fmtstr

validate_map_lookup_fmtstr:                       ; preds = %entry
  %1 = bitcast i32* %lookup_fmtstr_key to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i32 0, i32* %lookup_fmtstr_key, align 4
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %lookup_fmtstr_map = call %printf_t* inttoptr (i64 1 to %printf_t* (i64, i32*)*)(i64 %pseudo, i32* %lookup_fmtstr_key)
  %2 = bitcast i32* %lookup_fmtstr_key to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %2)
  %3 = sext %printf_t* %lookup_fmtstr_map to i32
  %4 = icmp ne i32 %3, 0
  br i1 %4, label %validate_map_lookup_fmtstr4, label %lookup_fmtstr_map_validate_failure

validate_map_lookup_fmtstr4:                      ; preds = %validate_map_lookup_fmtstr
  %5 = bitcast i32* %lookup_fmtstr_key5 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %5)
  store i32 0, i32* %lookup_fmtstr_key5, align 4
  %pseudo6 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %lookup_fmtstr_map7 = call %printf_t.0* inttoptr (i64 1 to %printf_t.0* (i64, i32*)*)(i64 %pseudo6, i32* %lookup_fmtstr_key5)
  %6 = bitcast i32* %lookup_fmtstr_key5 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %6)
  %7 = sext %printf_t.0* %lookup_fmtstr_map7 to i32
  %8 = icmp ne i32 %7, 0
  br i1 %8, label %post_hoist, label %lookup_fmtstr_map_validate_failure8

post_hoist:                                       ; preds = %validate_map_lookup_fmtstr4
  %get_pid_tgid = call i64 inttoptr (i64 14 to i64 ()*)()
  %9 = lshr i64 %get_pid_tgid, 32
  %10 = icmp ugt i64 %9, 10
  %11 = zext i1 %10 to i64
  %true_cond = icmp ne i64 %11, 0
  br i1 %true_cond, label %if_body, label %else_body

if_body:                                          ; preds = %post_hoist
  %12 = bitcast %printf_t* %lookup_fmtstr_map to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %12, i8 0, i64 8, i1 false)
  %13 = getelementptr %printf_t, %printf_t* %lookup_fmtstr_map, i32 0, i32 0
  store i64 0, i64* %13, align 8
  %pseudo2 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %perf_event_output3 = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %printf_t*, i64)*)(i8* %0, i64 %pseudo2, i64 4294967295, %printf_t* %lookup_fmtstr_map, i64 8)
  br label %if_end

if_end:                                           ; preds = %else_body, %if_body
  ret i64 0

else_body:                                        ; preds = %post_hoist
  %14 = bitcast %printf_t.0* %lookup_fmtstr_map7 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %14, i8 0, i64 8, i1 false)
  %15 = getelementptr %printf_t.0, %printf_t.0* %lookup_fmtstr_map7, i32 0, i32 0
  store i64 1, i64* %15, align 8
  %pseudo12 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %perf_event_output13 = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %printf_t.0*, i64)*)(i8* %0, i64 %pseudo12, i64 4294967295, %printf_t.0* %lookup_fmtstr_map7, i64 8)
  br label %if_end

lookup_fmtstr_map_validate_failure:               ; preds = %validate_map_lookup_fmtstr
  %16 = bitcast %helper_error_t* %helper_error_t to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %16)
  %17 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 0
  store i64 30006, i64* %17, align 8
  %18 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 1
  store i64 0, i64* %18, align 8
  %19 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 2
  store i32 %3, i32* %19, align 4
  %20 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 3
  store i8 1, i8* %20, align 1
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %helper_error_t*, i64)*)(i8* %0, i64 %pseudo1, i64 4294967295, %helper_error_t* %helper_error_t, i64 21)
  %21 = bitcast %helper_error_t* %helper_error_t to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %21)
  ret i64 0

lookup_fmtstr_map_validate_failure8:              ; preds = %validate_map_lookup_fmtstr4
  %22 = bitcast %helper_error_t* %helper_error_t9 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %22)
  %23 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t9, i64 0, i32 0
  store i64 30006, i64* %23, align 8
  %24 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t9, i64 0, i32 1
  store i64 1, i64* %24, align 8
  %25 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t9, i64 0, i32 2
  store i32 %7, i32* %25, align 4
  %26 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t9, i64 0, i32 3
  store i8 1, i8* %26, align 1
  %pseudo10 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %perf_event_output11 = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %helper_error_t*, i64)*)(i8* %0, i64 %pseudo10, i64 4294967295, %helper_error_t* %helper_error_t9, i64 21)
  %27 = bitcast %helper_error_t* %helper_error_t9 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %27)
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
