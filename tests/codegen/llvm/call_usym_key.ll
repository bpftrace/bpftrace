; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%usym_t = type { i64, i64, i64 }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"kprobe:f"(i8* %0) section "s_kprobe:f_1" {
entry:
  %initial_value = alloca i64, align 8
  %usym = alloca %usym_t, align 8
  %1 = bitcast %usym_t* %usym to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  %get_pid_tgid = call i64 inttoptr (i64 14 to i64 ()*)()
  %2 = lshr i64 %get_pid_tgid, 32
  %3 = getelementptr %usym_t, %usym_t* %usym, i64 0, i32 0
  %4 = getelementptr %usym_t, %usym_t* %usym, i64 0, i32 1
  %5 = getelementptr %usym_t, %usym_t* %usym, i64 0, i32 2
  store i64 0, i64* %3, align 8
  store i64 %2, i64* %4, align 8
  store i64 0, i64* %5, align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i64, %usym_t*)*)(i64 %pseudo, %usym_t* %usym)
  %cast = bitcast i8* %lookup_elem to i64*
  %6 = icmp eq i64* %cast, null
  br i1 %6, label %ptr_null, label %ptr_merge

ptr_null:                                         ; preds = %entry
  %7 = bitcast i64* %initial_value to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %7)
  store i64 0, i64* %initial_value, align 8
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, %usym_t*, i64*, i64)*)(i64 %pseudo1, %usym_t* %usym, i64* %initial_value, i64 0)
  %pseudo2 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %lookup_elem3 = call i8* inttoptr (i64 1 to i8* (i64, %usym_t*)*)(i64 %pseudo2, %usym_t* %usym)
  %cast4 = bitcast i8* %lookup_elem3 to i64*
  %8 = bitcast i64* %initial_value to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %8)
  br label %ptr_merge

ptr_merge:                                        ; preds = %ptr_null, %entry
  %9 = icmp ne i64* %cast4, null
  br i1 %9, label %ptr_not_null, label %merge

ptr_not_null:                                     ; preds = %ptr_merge
  %10 = load i64, i64* %cast4, align 8
  %11 = add i64 %10, 1
  store i64 %11, i64* %cast4, align 8
  br label %merge

merge:                                            ; preds = %ptr_not_null, %ptr_merge
  %12 = bitcast %usym_t* %usym to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %12)
  ret i64 0
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }
