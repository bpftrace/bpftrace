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
  %sarg2 = alloca i64
  %"@x_val" = alloca i64
  %"@x_key" = alloca i64
  %sarg0 = alloca i64
  %1 = bitcast i8* %0 to i64*
  %2 = getelementptr i64, i64* %1, i64 19
  %reg_sp = load volatile i64, i64* %2
  %3 = bitcast i64* %sarg0 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %3)
  %4 = add i64 %reg_sp, 8
  %probe_read = call i64 inttoptr (i64 4 to i64 (i64*, i32, i64)*)(i64* %sarg0, i32 8, i64 %4)
  %5 = load i64, i64* %sarg0
  %6 = bitcast i64* %sarg0 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %6)
  %7 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %7)
  store i64 0, i64* %"@x_key"
  %8 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %8)
  store i64 %5, i64* %"@x_val"
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo, i64* %"@x_key", i64* %"@x_val", i64 0)
  %9 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %9)
  %10 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %10)
  %11 = bitcast i8* %0 to i64*
  %12 = getelementptr i64, i64* %11, i64 19
  %reg_sp1 = load volatile i64, i64* %12
  %13 = bitcast i64* %sarg2 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %13)
  %14 = add i64 %reg_sp1, 24
  %probe_read2 = call i64 inttoptr (i64 4 to i64 (i64*, i32, i64)*)(i64* %sarg2, i32 8, i64 %14)
  %15 = load i64, i64* %sarg2
  %16 = bitcast i64* %sarg2 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %16)
  %17 = bitcast i64* %"@y_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %17)
  store i64 0, i64* %"@y_key"
  %18 = bitcast i64* %"@y_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %18)
  store i64 %15, i64* %"@y_val"
  %pseudo3 = call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  %update_elem4 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo3, i64* %"@y_key", i64* %"@y_val", i64 0)
  %19 = bitcast i64* %"@y_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %19)
  %20 = bitcast i64* %"@y_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %20)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
