; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"iter:task_file"(i8* %0) section "s_iter:task_file_1" {
entry:
  %"@_val" = alloca i64, align 8
  %lookup_elem_val = alloca i64, align 8
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
  %9 = bitcast i64* %lookup_elem_val to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %9)
  %map_lookup_cond = icmp ne i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %pred_true
  %cast = bitcast i8* %lookup_elem to i64*
  %10 = load i64, i64* %cast, align 8
  store i64 %10, i64* %lookup_elem_val, align 8
  br label %lookup_merge

lookup_failure:                                   ; preds = %pred_true
  store i64 0, i64* %lookup_elem_val, align 8
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  %11 = load i64, i64* %lookup_elem_val, align 8
  %12 = bitcast i64* %lookup_elem_val to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %12)
  %13 = bitcast i64* %"@_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %13)
  %14 = add i64 %11, 1
  store i64 %14, i64* %"@_val", align 8
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo1, i64* %"@_key", i64* %"@_val", i64 0)
  %15 = bitcast i64* %"@_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %15)
  %16 = bitcast i64* %"@_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %16)
  ret i64 0
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }
