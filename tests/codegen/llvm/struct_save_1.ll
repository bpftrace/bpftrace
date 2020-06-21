; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

define i64 @"kprobe:f"(i8*) section "s_kprobe:f_1" {
entry:
  %"@foo_val" = alloca [12 x i8]
  %"@foo_key" = alloca i64
  %1 = bitcast i64* %"@foo_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 0, i64* %"@foo_key"
  %2 = bitcast [12 x i8]* %"@foo_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %2)
  %probe_read = call i64 inttoptr (i64 4 to i64 ([12 x i8]*, i32, i64)*)([12 x i8]* %"@foo_val", i32 12, i64 0)
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, [12 x i8]*, i64)*)(i64 %pseudo, i64* %"@foo_key", [12 x i8]* %"@foo_val", i64 0)
  %3 = bitcast i64* %"@foo_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %3)
  %4 = bitcast [12 x i8]* %"@foo_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %4)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
