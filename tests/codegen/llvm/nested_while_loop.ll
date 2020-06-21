; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

define i64 @"interval:s:1"(i8*) section "s_interval:s:1_1" {
entry:
  %"@_newval" = alloca i64
  %lookup_elem_val = alloca i64
  %"@_key" = alloca i64
  %"$j" = alloca i64
  %1 = bitcast i64* %"$j" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 0, i64* %"$j"
  %"$i" = alloca i64
  %2 = bitcast i64* %"$i" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %2)
  store i64 0, i64* %"$i"
  %3 = bitcast i64* %"$i" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %3)
  store i64 1, i64* %"$i"
  br label %while_cond

while_cond:                                       ; preds = %while_end3, %entry
  %4 = load i64, i64* %"$i"
  %5 = icmp sle i64 %4, 100
  %6 = zext i1 %5 to i64
  %true_cond = icmp ne i64 %6, 0
  br i1 %true_cond, label %while_body, label %while_end

while_body:                                       ; preds = %while_cond
  %7 = bitcast i64* %"$j" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %7)
  store i64 0, i64* %"$j"
  %8 = load i64, i64* %"$i"
  %9 = add i64 %8, 1
  store i64 %9, i64* %"$i"
  br label %while_cond1

while_end:                                        ; preds = %while_cond
  ret i64 0

while_cond1:                                      ; preds = %lookup_merge, %while_body
  %10 = load i64, i64* %"$j"
  %11 = icmp sle i64 %10, 100
  %12 = zext i1 %11 to i64
  %true_cond4 = icmp ne i64 %12, 0
  br i1 %true_cond4, label %while_body2, label %while_end3

while_body2:                                      ; preds = %while_cond1
  %13 = bitcast i64* %"@_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %13)
  store i64 0, i64* %"@_key"
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo, i64* %"@_key")
  %14 = bitcast i64* %lookup_elem_val to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %14)
  %map_lookup_cond = icmp ne i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

while_end3:                                       ; preds = %while_cond1
  br label %while_cond

lookup_success:                                   ; preds = %while_body2
  %cast = bitcast i8* %lookup_elem to i64*
  %15 = load i64, i64* %cast
  store i64 %15, i64* %lookup_elem_val
  br label %lookup_merge

lookup_failure:                                   ; preds = %while_body2
  store i64 0, i64* %lookup_elem_val
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  %16 = load i64, i64* %lookup_elem_val
  %17 = bitcast i64* %"@_newval" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %17)
  %18 = add i64 %16, 1
  store i64 %18, i64* %"@_newval"
  %pseudo5 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo5, i64* %"@_key", i64* %"@_newval", i64 0)
  %19 = bitcast i64* %"@_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %19)
  %20 = bitcast i64* %"@_newval" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %20)
  %21 = load i64, i64* %"$j"
  %22 = add i64 %21, 1
  store i64 %22, i64* %"$j"
  br label %while_cond1
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
