; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

define i64 @"kprobe:f"(i8*) section "s_kprobe:f_1" {
entry:
  %"@y_val" = alloca i64
  %"@y_key" = alloca i64
  %"@x_val" = alloca i64
  %"@x_key" = alloca i64
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 4)
  %get_stackid = call i64 inttoptr (i64 27 to i64 (i8*, i64, i64)*)(i8* %0, i64 %pseudo, i64 256)
  %get_pid_tgid = call i64 inttoptr (i64 14 to i64 ()*)()
  %1 = shl i64 %get_pid_tgid, 32
  %2 = or i64 %get_stackid, %1
  %3 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %3)
  store i64 0, i64* %"@x_key"
  %4 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %4)
  store i64 %2, i64* %"@x_val"
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo1, i64* %"@x_key", i64* %"@x_val", i64 0)
  %5 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %5)
  %6 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %6)
  %pseudo2 = call i64 @llvm.bpf.pseudo(i64 1, i64 3)
  %get_stackid3 = call i64 inttoptr (i64 27 to i64 (i8*, i64, i64)*)(i8* %0, i64 %pseudo2, i64 256)
  %get_pid_tgid4 = call i64 inttoptr (i64 14 to i64 ()*)()
  %7 = shl i64 %get_pid_tgid4, 32
  %8 = or i64 %get_stackid3, %7
  %9 = bitcast i64* %"@y_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %9)
  store i64 0, i64* %"@y_key"
  %10 = bitcast i64* %"@y_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %10)
  store i64 %8, i64* %"@y_val"
  %pseudo5 = call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  %update_elem6 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo5, i64* %"@y_key", i64* %"@y_val", i64 0)
  %11 = bitcast i64* %"@y_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %11)
  %12 = bitcast i64* %"@y_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %12)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
