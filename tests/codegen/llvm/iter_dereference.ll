; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"iter:task_file"(i8* %0) section "s_iter:task_file_1" {
entry:
  %initial_value = alloca i64, align 8
  %"@_key" = alloca i64, align 8
  %1 = ptrtoint i8* %0 to i64
  %2 = add i64 %1, 0
  %3 = inttoptr i64 %2 to i64*
  %4 = load volatile i64, i64* %3, align 8
  %predcond = icmp eq i64 %4, 0
  br i1 %predcond, label %pred_false, label %pred_true

pred_false:                                       ; preds = %entry
  ret i64 0

pred_true:                                        ; preds = %entry
  %5 = add i64 %4, 8
  %6 = inttoptr i64 %5 to i64*
  %7 = load volatile i64, i64* %6, align 8
  %8 = bitcast i64* %"@_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %8)
  store i64 %7, i64* %"@_key", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo, i64* %"@_key")
  %cast = bitcast i8* %lookup_elem to i64*
  %9 = icmp eq i64* %cast, null
  br i1 %9, label %ptr_null, label %ptr_merge

ptr_null:                                         ; preds = %pred_true
  %10 = bitcast i64* %initial_value to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %10)
  store i64 0, i64* %initial_value, align 8
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo1, i64* %"@_key", i64* %initial_value, i64 0)
  %pseudo2 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %lookup_elem3 = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo2, i64* %"@_key")
  %cast4 = bitcast i8* %lookup_elem3 to i64*
  %11 = bitcast i64* %initial_value to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %11)
  br label %ptr_merge

ptr_merge:                                        ; preds = %ptr_null, %pred_true
  %12 = icmp ne i64* %cast4, null
  br i1 %12, label %ptr_not_null, label %merge

ptr_not_null:                                     ; preds = %ptr_merge
  %13 = load i64, i64* %cast4, align 8
  %14 = add i64 %13, 1
  store i64 %14, i64* %cast4, align 8
  br label %merge

merge:                                            ; preds = %ptr_not_null, %ptr_merge
  %15 = bitcast i64* %"@_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %15)
  ret i64 0
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }
