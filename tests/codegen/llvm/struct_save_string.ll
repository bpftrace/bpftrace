; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

define i64 @"kprobe:f"(i8*) section "s_kprobe:f_1" {
entry:
  %"@str_key" = alloca i64
  %lookup_elem_val = alloca [32 x i8]
  %"@foo_key1" = alloca i64
  %"@foo_val" = alloca [32 x i8]
  %"@foo_key" = alloca i64
  %1 = bitcast i64* %"@foo_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 0, i64* %"@foo_key"
  %2 = bitcast [32 x i8]* %"@foo_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %2)
  %probe_read = call i64 inttoptr (i64 4 to i64 ([32 x i8]*, i32, i64)*)([32 x i8]* %"@foo_val", i32 32, i64 0)
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, [32 x i8]*, i64)*)(i64 %pseudo, i64* %"@foo_key", [32 x i8]* %"@foo_val", i64 0)
  %3 = bitcast i64* %"@foo_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %3)
  %4 = bitcast [32 x i8]* %"@foo_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %4)
  %5 = bitcast i64* %"@foo_key1" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %5)
  store i64 0, i64* %"@foo_key1"
  %pseudo2 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo2, i64* %"@foo_key1")
  %6 = bitcast [32 x i8]* %lookup_elem_val to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %6)
  %map_lookup_cond = icmp ne i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  %7 = bitcast [32 x i8]* %lookup_elem_val to i8*
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* align 1 %7, i8* align 1 %lookup_elem, i64 32, i1 false)
  br label %lookup_merge

lookup_failure:                                   ; preds = %entry
  %8 = bitcast [32 x i8]* %lookup_elem_val to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %8, i8 0, i64 32, i1 false)
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  %9 = bitcast i64* %"@foo_key1" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %9)
  %10 = getelementptr [32 x i8], [32 x i8]* %lookup_elem_val, i64 0, i64 0
  %11 = bitcast i64* %"@str_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %11)
  store i64 0, i64* %"@str_key"
  %pseudo3 = call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  %update_elem4 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i8*, i64)*)(i64 %pseudo3, i64* %"@str_key", i8* %10, i64 0)
  %12 = bitcast i64* %"@str_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %12)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %10)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.memcpy.p0i8.p0i8.i64(i8* nocapture writeonly, i8* nocapture readonly, i64, i1) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
