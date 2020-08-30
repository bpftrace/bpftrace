; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

define i64 @"kprobe:f"(i8*) section "s_kprobe:f_1" {
entry:
  %"@x_key" = alloca [24 x i8]
  %"@x_val" = alloca i64
  %1 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 44, i64* %"@x_val"
  %2 = bitcast [24 x i8]* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %2)
  %3 = getelementptr [24 x i8], [24 x i8]* %"@x_key", i64 0, i64 0
  %4 = bitcast i8* %3 to i64*
  store i64 11, i64* %4
  %5 = getelementptr [24 x i8], [24 x i8]* %"@x_key", i64 0, i64 8
  %6 = bitcast i8* %5 to i64*
  store i64 22, i64* %6
  %7 = getelementptr [24 x i8], [24 x i8]* %"@x_key", i64 0, i64 16
  %8 = bitcast i8* %7 to i64*
  store i64 33, i64* %8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, [24 x i8]*, i64*, i64)*)(i64 %pseudo, [24 x i8]* %"@x_key", i64* %"@x_val", i64 0)
  %9 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %9)
  %10 = bitcast [24 x i8]* %"@x_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %10)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
