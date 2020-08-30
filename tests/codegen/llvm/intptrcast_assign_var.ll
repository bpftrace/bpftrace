; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

define i64 @"kretprobe:f"(i8*) section "s_kretprobe:f_1" {
entry:
  %"@_key" = alloca i64
  %"@_val" = alloca i64
  %deref = alloca i8
  %1 = bitcast i8* %0 to i64*
  %2 = getelementptr i64, i64* %1, i64 4
  %reg_bp = load volatile i64, i64* %2
  %3 = sub i64 %reg_bp, 1
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %deref)
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i32, i64)*)(i8* %deref, i32 1, i64 %3)
  %4 = load i8, i8* %deref
  %5 = sext i8 %4 to i64
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %deref)
  %6 = bitcast i64* %"@_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %6)
  store i64 %5, i64* %"@_val"
  %7 = bitcast i64* %"@_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %7)
  store i64 0, i64* %"@_key"
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo, i64* %"@_key", i64* %"@_val", i64 0)
  %8 = bitcast i64* %"@_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %8)
  %9 = bitcast i64* %"@_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %9)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
