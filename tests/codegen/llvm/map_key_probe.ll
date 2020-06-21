; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

define i64 @"tracepoint:sched:sched_one"(i8*) section "s_tracepoint:sched:sched_one_1" {
entry:
  %"@x_val" = alloca i64
  %"@x_key1" = alloca [8 x i8]
  %lookup_elem_val = alloca i64
  %"@x_key" = alloca [8 x i8]
  %1 = bitcast [8 x i8]* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  %2 = bitcast [8 x i8]* %"@x_key" to i64*
  store i64 0, i64* %2
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i64, [8 x i8]*)*)(i64 %pseudo, [8 x i8]* %"@x_key")
  %3 = bitcast i64* %lookup_elem_val to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %3)
  %map_lookup_cond = icmp ne i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  %cast = bitcast i8* %lookup_elem to i64*
  %4 = load i64, i64* %cast
  store i64 %4, i64* %lookup_elem_val
  br label %lookup_merge

lookup_failure:                                   ; preds = %entry
  store i64 0, i64* %lookup_elem_val
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  %5 = load i64, i64* %lookup_elem_val
  %6 = bitcast [8 x i8]* %"@x_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %6)
  %7 = add i64 %5, 1
  %8 = bitcast [8 x i8]* %"@x_key1" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %8)
  %9 = bitcast [8 x i8]* %"@x_key1" to i64*
  store i64 0, i64* %9
  %10 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %10)
  store i64 %7, i64* %"@x_val"
  %pseudo2 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, [8 x i8]*, i64*, i64)*)(i64 %pseudo2, [8 x i8]* %"@x_key1", i64* %"@x_val", i64 0)
  %11 = bitcast [8 x i8]* %"@x_key1" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %11)
  %12 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %12)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

define i64 @"tracepoint:sched:sched_two"(i8*) section "s_tracepoint:sched:sched_two_2" {
entry:
  %"@x_val" = alloca i64
  %"@x_key1" = alloca [8 x i8]
  %lookup_elem_val = alloca i64
  %"@x_key" = alloca [8 x i8]
  %1 = bitcast [8 x i8]* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  %2 = bitcast [8 x i8]* %"@x_key" to i64*
  store i64 1, i64* %2
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i64, [8 x i8]*)*)(i64 %pseudo, [8 x i8]* %"@x_key")
  %3 = bitcast i64* %lookup_elem_val to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %3)
  %map_lookup_cond = icmp ne i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  %cast = bitcast i8* %lookup_elem to i64*
  %4 = load i64, i64* %cast
  store i64 %4, i64* %lookup_elem_val
  br label %lookup_merge

lookup_failure:                                   ; preds = %entry
  store i64 0, i64* %lookup_elem_val
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  %5 = load i64, i64* %lookup_elem_val
  %6 = bitcast [8 x i8]* %"@x_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %6)
  %7 = add i64 %5, 1
  %8 = bitcast [8 x i8]* %"@x_key1" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %8)
  %9 = bitcast [8 x i8]* %"@x_key1" to i64*
  store i64 1, i64* %9
  %10 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %10)
  store i64 %7, i64* %"@x_val"
  %pseudo2 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, [8 x i8]*, i64*, i64)*)(i64 %pseudo2, [8 x i8]* %"@x_key1", i64* %"@x_val", i64 0)
  %11 = bitcast [8 x i8]* %"@x_key1" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %11)
  %12 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %12)
  ret i64 0
}

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
