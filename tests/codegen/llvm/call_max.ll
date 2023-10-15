; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"kprobe:f"(i8* %0) section "s_kprobe:f_1" {
entry:
  %initial_value = alloca i64, align 8
  %"@x_key" = alloca i64, align 8
  %1 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 0, i64* %"@x_key", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo, i64* %"@x_key")
  %cast = bitcast i8* %lookup_elem to i64*
  %2 = icmp eq i64* %cast, null
  br i1 %2, label %ptr_null, label %ptr_merge

ptr_null:                                         ; preds = %entry
  %3 = bitcast i64* %initial_value to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %3)
  store i64 0, i64* %initial_value, align 8
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo1, i64* %"@x_key", i64* %initial_value, i64 0)
  %pseudo2 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %lookup_elem3 = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo2, i64* %"@x_key")
  %cast4 = bitcast i8* %lookup_elem3 to i64*
  %4 = bitcast i64* %initial_value to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %4)
  br label %ptr_merge

ptr_merge:                                        ; preds = %ptr_null, %entry
  %5 = icmp ne i64* %cast4, null
  br i1 %5, label %ptr_not_null, label %ptr_merge5

ptr_not_null:                                     ; preds = %ptr_merge
  %get_pid_tgid = call i64 inttoptr (i64 14 to i64 ()*)()
  %6 = lshr i64 %get_pid_tgid, 32
  %7 = load i64, i64* %cast4, align 8
  %8 = icmp sge i64 %6, %7
  br i1 %8, label %min.ge, label %min.lt

ptr_merge5:                                       ; preds = %min.lt, %ptr_merge
  %9 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %9)
  ret i64 0

min.lt:                                           ; preds = %min.ge, %ptr_not_null
  br label %ptr_merge5

min.ge:                                           ; preds = %ptr_not_null
  store i64 %6, i64* %cast4, align 8
  br label %min.lt
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }
