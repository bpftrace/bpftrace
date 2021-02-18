; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

define i64 @"kprobe:f"(i8*) section "s_kprobe:f_1" {
entry:
  %"@x_key" = alloca i64
  %macaddr = alloca [6 x i8]
  %1 = bitcast [6 x i8]* %macaddr to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  %2 = bitcast [6 x i8]* %macaddr to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %2, i8 0, i64 6, i1 false)
  %3 = bitcast [6 x i8]* %macaddr to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %3)
  %probe_read_kernel = call i64 inttoptr (i64 113 to i64 ([6 x i8]*, i32, i64)*)([6 x i8]* %macaddr, i32 6, i64 0)
  %4 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %4)
  store i64 0, i64* %"@x_key"
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, [6 x i8]*, i64)*)(i64 %pseudo, i64* %"@x_key", [6 x i8]* %macaddr, i64 0)
  %5 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %5)
  %6 = bitcast [6 x i8]* %macaddr to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %6)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i1) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
