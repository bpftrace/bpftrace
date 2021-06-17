; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%helper_error_t = type <{ i64, i64, i32, i8 }>
%printf_t = type { i64 }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"kprobe:f"(i8* %0) section "s_kprobe:f_1" {
entry:
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
  br i1 %4, label %post_hoist, label %lookup_fmtstr_map_validate_failure

post_hoist:                                       ; preds = %validate_map_lookup_fmtstr
  %get_pid_tgid = call i64 inttoptr (i64 14 to i64 ()*)()
  %5 = lshr i64 %get_pid_tgid, 32
  %6 = icmp ugt i64 %5, 10000
  %7 = zext i1 %6 to i64
  %true_cond = icmp ne i64 %7, 0
  br i1 %true_cond, label %if_body, label %if_end

if_body:                                          ; preds = %post_hoist
  %get_pid_tgid3 = call i64 inttoptr (i64 14 to i64 ()*)()
  %8 = lshr i64 %get_pid_tgid3, 32
  %9 = urem i64 %8, 2
  %10 = icmp eq i64 %9, 0
  %11 = zext i1 %10 to i64
  %true_cond4 = icmp ne i64 %11, 0
  br i1 %true_cond4, label %if_body1, label %if_end2

if_end:                                           ; preds = %if_end2, %post_hoist
  ret i64 0

if_body1:                                         ; preds = %if_body
  %12 = bitcast %printf_t* %lookup_fmtstr_map to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %12, i8 0, i64 8, i1 false)
  %13 = getelementptr %printf_t, %printf_t* %lookup_fmtstr_map, i32 0, i32 0
  store i64 0, i64* %13, align 8
  %pseudo6 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %perf_event_output7 = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %printf_t*, i64)*)(i8* %0, i64 %pseudo6, i64 4294967295, %printf_t* %lookup_fmtstr_map, i64 8)
  br label %if_end2

if_end2:                                          ; preds = %if_body1, %if_body
  br label %if_end

lookup_fmtstr_map_validate_failure:               ; preds = %validate_map_lookup_fmtstr
  %14 = bitcast %helper_error_t* %helper_error_t to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %14)
  %15 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 0
  store i64 30006, i64* %15, align 8
  %16 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 1
  store i64 0, i64* %16, align 8
  %17 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 2
  store i32 %3, i32* %17, align 4
  %18 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 3
  store i8 1, i8* %18, align 1
  %pseudo5 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %helper_error_t*, i64)*)(i8* %0, i64 %pseudo5, i64 4294967295, %helper_error_t* %helper_error_t, i64 21)
  %19 = bitcast %helper_error_t* %helper_error_t to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %19)
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
