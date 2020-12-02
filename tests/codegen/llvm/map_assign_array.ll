; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

define i64 @"kprobe:f"(i8*) section "s_kprobe:f_1" {
entry:
  %"$var" = alloca i32
  %1 = bitcast i32* %"$var" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i32 0, i32* %"$var"
  %lookup_elem_val = alloca [4 x i32]
  %"@x_key1" = alloca [8 x i8]
  %"@x_val" = alloca [4 x i32]
  %"@x_key" = alloca [8 x i8]
  %2 = bitcast i8* %0 to i64*
  %3 = getelementptr i64, i64* %2, i64 14
  %arg0 = load volatile i64, i64* %3
  %4 = add i64 %arg0, 0
  %5 = bitcast [8 x i8]* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %5)
  %6 = bitcast [8 x i8]* %"@x_key" to i64*
  store i64 0, i64* %6
  %7 = bitcast [4 x i32]* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %7)
  %probe_read_kernel = call i64 inttoptr (i64 113 to i64 ([4 x i32]*, i32, i64)*)([4 x i32]* %"@x_val", i32 16, i64 %4)
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, [8 x i8]*, [4 x i32]*, i64)*)(i64 %pseudo, [8 x i8]* %"@x_key", [4 x i32]* %"@x_val", i64 0)
  %8 = bitcast [8 x i8]* %"@x_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %8)
  %9 = bitcast [4 x i32]* %"@x_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %9)
  %10 = bitcast [8 x i8]* %"@x_key1" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %10)
  %11 = bitcast [8 x i8]* %"@x_key1" to i64*
  store i64 0, i64* %11
  %pseudo2 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i64, [8 x i8]*)*)(i64 %pseudo2, [8 x i8]* %"@x_key1")
  %12 = bitcast [4 x i32]* %lookup_elem_val to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %12)
  %map_lookup_cond = icmp ne i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  %13 = bitcast [4 x i32]* %lookup_elem_val to i8*
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* align 1 %13, i8* align 1 %lookup_elem, i64 16, i1 false)
  br label %lookup_merge

lookup_failure:                                   ; preds = %entry
  %14 = bitcast [4 x i32]* %lookup_elem_val to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %14, i8 0, i64 16, i1 false)
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  %15 = bitcast [8 x i8]* %"@x_key1" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %15)
  %16 = ptrtoint [4 x i32]* %lookup_elem_val to i64
  %17 = add i64 %16, 0
  %18 = inttoptr i64 %17 to i32*
  %19 = load volatile i32, i32* %18
  %20 = bitcast [4 x i32]* %lookup_elem_val to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %20)
  %21 = bitcast i32* %"$var" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %21)
  store i32 %19, i32* %"$var"
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
