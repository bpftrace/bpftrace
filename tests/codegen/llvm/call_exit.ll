; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

define i64 @"kprobe:f"(i8*) section "s_kprobe:f_1" {
entry:
  %"@_val" = alloca i64
  %"@_key" = alloca i64
  %perfdata = alloca i64
  %1 = bitcast i64* %perfdata to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 30000, i64* %perfdata
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, i64*, i64)*)(i8* %0, i64 %pseudo, i64 4294967295, i64* %perfdata, i64 8)
  %2 = bitcast i64* %perfdata to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %2)
  ret i64 0

deadcode:                                         ; No predecessors!
  %3 = bitcast i64* %"@_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %3)
  store i64 0, i64* %"@_key"
  %4 = bitcast i64* %"@_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %4)
  store i64 10, i64* %"@_val"
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo1, i64* %"@_key", i64* %"@_val", i64 0)
  %5 = bitcast i64* %"@_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %5)
  %6 = bitcast i64* %"@_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %6)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
