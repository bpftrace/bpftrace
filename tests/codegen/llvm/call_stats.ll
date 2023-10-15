; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"kprobe:f"(i8* %0) section "s_kprobe:f_1" {
entry:
  %initial_value11 = alloca i64, align 8
  %"@x_key5" = alloca i64, align 8
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
  br i1 %5, label %count_ptr_not_null, label %count_ptr_merge

count_ptr_not_null:                               ; preds = %ptr_merge
  %6 = load i64, i64* %cast4, align 8
  %7 = add i64 %6, 1
  store i64 %7, i64* %cast4, align 8
  %8 = bitcast i64* %"@x_key5" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %8)
  store i64 1, i64* %"@x_key5", align 8
  %pseudo6 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %lookup_elem7 = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo6, i64* %"@x_key5")
  %cast10 = bitcast i8* %lookup_elem7 to i64*
  %9 = icmp eq i64* %cast10, null
  br i1 %9, label %ptr_null8, label %ptr_merge9

count_ptr_merge:                                  ; preds = %total_ptr_merge, %ptr_merge
  %10 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %10)
  ret i64 0

ptr_null8:                                        ; preds = %count_ptr_not_null
  %11 = bitcast i64* %initial_value11 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %11)
  store i64 0, i64* %initial_value11, align 8
  %pseudo12 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem13 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo12, i64* %"@x_key5", i64* %initial_value11, i64 0)
  %pseudo14 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %lookup_elem15 = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo14, i64* %"@x_key5")
  %cast16 = bitcast i8* %lookup_elem15 to i64*
  %12 = bitcast i64* %initial_value11 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %12)
  br label %ptr_merge9

ptr_merge9:                                       ; preds = %ptr_null8, %count_ptr_not_null
  %13 = icmp ne i64* %cast16, null
  br i1 %13, label %total_ptr_not_null, label %total_ptr_merge

total_ptr_not_null:                               ; preds = %ptr_merge9
  %get_pid_tgid = call i64 inttoptr (i64 14 to i64 ()*)()
  %14 = lshr i64 %get_pid_tgid, 32
  %15 = load i64, i64* %cast16, align 8
  %16 = add i64 %14, %15
  store i64 %16, i64* %cast16, align 8
  br label %total_ptr_merge

total_ptr_merge:                                  ; preds = %total_ptr_not_null, %ptr_merge9
  %17 = bitcast i64* %"@x_key5" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %17)
  br label %count_ptr_merge
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }
