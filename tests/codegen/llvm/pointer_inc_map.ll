; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"kprobe:f"(i8* %0) section "s_kprobe:f_1" {
entry:
  %"@_newval" = alloca i64, align 8
  %lookup_elem_val9 = alloca i64, align 8
  %"@_key3" = alloca i64, align 8
  %lookup_elem_val = alloca i64, align 8
  %"@_key1" = alloca i64, align 8
  %"@_ptr" = alloca i64, align 8
  %"@_key" = alloca i64, align 8
  %1 = bitcast i64* %"@_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 0, i64* %"@_key", align 8
  %2 = bitcast i64* %"@_ptr" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %2)
  store i64 1000, i64* %"@_ptr", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo, i64* %"@_key", i64* %"@_ptr", i64 0)
  %3 = bitcast i64* %"@_ptr" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %3)
  %4 = bitcast i64* %"@_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %4)
  %5 = bitcast i64* %"@_key1" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %5)
  store i64 0, i64* %"@_key1", align 8
  %pseudo2 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo2, i64* %"@_key1")
  %6 = bitcast i64* %lookup_elem_val to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %6)
  %map_lookup_cond = icmp ne i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  %cast = bitcast i8* %lookup_elem to i64*
  %7 = load i64, i64* %cast, align 8
  store i64 %7, i64* %lookup_elem_val, align 8
  br label %lookup_merge

lookup_failure:                                   ; preds = %entry
  store i64 0, i64* %lookup_elem_val, align 8
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  %8 = load i64, i64* %lookup_elem_val, align 8
  %9 = bitcast i64* %lookup_elem_val to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %9)
  %10 = bitcast i64* %"@_key1" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %10)
  %11 = bitcast i64* %"@_key3" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %11)
  store i64 0, i64* %"@_key3", align 8
  %pseudo4 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %lookup_elem5 = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo4, i64* %"@_key3")
  %12 = bitcast i64* %lookup_elem_val9 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %12)
  %map_lookup_cond10 = icmp ne i8* %lookup_elem5, null
  br i1 %map_lookup_cond10, label %lookup_success6, label %lookup_failure7

lookup_success6:                                  ; preds = %lookup_merge
  %cast11 = bitcast i8* %lookup_elem5 to i64*
  %13 = load i64, i64* %cast11, align 8
  store i64 %13, i64* %lookup_elem_val9, align 8
  br label %lookup_merge8

lookup_failure7:                                  ; preds = %lookup_merge
  store i64 0, i64* %lookup_elem_val9, align 8
  br label %lookup_merge8

lookup_merge8:                                    ; preds = %lookup_failure7, %lookup_success6
  %14 = load i64, i64* %lookup_elem_val9, align 8
  %15 = bitcast i64* %lookup_elem_val9 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %15)
  %16 = bitcast i64* %"@_newval" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %16)
  %17 = add i64 %14, 2
  store i64 %17, i64* %"@_newval", align 8
  %pseudo12 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem13 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo12, i64* %"@_key3", i64* %"@_newval", i64 0)
  %18 = bitcast i64* %"@_newval" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %18)
  %19 = bitcast i64* %"@_key3" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %19)
  ret i64 0
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }
