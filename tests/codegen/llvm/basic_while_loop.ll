; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

define i64 @"interval:s:1"(i8*) section "s_interval:s:1_1" {
entry:
  %"@_val" = alloca i64
  %"@_key" = alloca i64
  %"$a" = alloca i64
  %1 = bitcast i64* %"$a" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 0, i64* %"$a"
  %2 = bitcast i64* %"$a" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %2)
  store i64 1, i64* %"$a"
  br label %while_cond

while_cond:                                       ; preds = %while_body, %entry
  %3 = load i64, i64* %"$a"
  %4 = icmp sle i64 %3, 150
  %5 = zext i1 %4 to i64
  %true_cond = icmp ne i64 %5, 0
  br i1 %true_cond, label %while_body, label %while_end

while_body:                                       ; preds = %while_cond
  %6 = load i64, i64* %"$a"
  %7 = add i64 %6, 1
  store i64 %7, i64* %"$a"
  %8 = bitcast i64* %"@_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %8)
  store i64 0, i64* %"@_key"
  %9 = bitcast i64* %"@_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %9)
  store i64 %6, i64* %"@_val"
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo, i64* %"@_key", i64* %"@_val", i64 0)
  %10 = bitcast i64* %"@_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %10)
  %11 = bitcast i64* %"@_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %11)
  br label %while_cond

while_end:                                        ; preds = %while_cond
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
