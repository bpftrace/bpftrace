; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"kprobe:f"(i8* %0) section "s_kprobe:f_1" {
entry:
  %"@x_val" = alloca i64, align 8
  %"@x_key" = alloca i64, align 8
  %lookup_elem_val11 = alloca [16 x i8], align 1
  %"@foo_key5" = alloca i64, align 8
  %"@bar_key" = alloca i64, align 8
  %lookup_elem_val = alloca [16 x i8], align 1
  %"@foo_key1" = alloca i64, align 8
  %"@foo_val" = alloca [16 x i8], align 1
  %"@foo_key" = alloca i64, align 8
  %1 = bitcast i8* %0 to i64*
  %2 = getelementptr i64, i64* %1, i64 14
  %arg0 = load volatile i64, i64* %2, align 8
  %3 = bitcast i64* %"@foo_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %3)
  store i64 0, i64* %"@foo_key", align 8
  %4 = bitcast [16 x i8]* %"@foo_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %4)
  %probe_read_kernel = call i64 inttoptr (i64 113 to i64 ([16 x i8]*, i32, i64)*)([16 x i8]* %"@foo_val", i32 16, i64 %arg0)
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, [16 x i8]*, i64)*)(i64 %pseudo, i64* %"@foo_key", [16 x i8]* %"@foo_val", i64 0)
  %5 = bitcast [16 x i8]* %"@foo_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %5)
  %6 = bitcast i64* %"@foo_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %6)
  %7 = bitcast i64* %"@foo_key1" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %7)
  store i64 0, i64* %"@foo_key1", align 8
  %pseudo2 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo2, i64* %"@foo_key1")
  %8 = bitcast [16 x i8]* %lookup_elem_val to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %8)
  %map_lookup_cond = icmp ne i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  %9 = bitcast [16 x i8]* %lookup_elem_val to i8*
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* align 1 %9, i8* align 1 %lookup_elem, i64 16, i1 false)
  br label %lookup_merge

lookup_failure:                                   ; preds = %entry
  %10 = bitcast [16 x i8]* %lookup_elem_val to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %10, i8 0, i64 16, i1 false)
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  %11 = bitcast i64* %"@foo_key1" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %11)
  %12 = getelementptr [16 x i8], [16 x i8]* %lookup_elem_val, i32 0, i64 4
  %13 = bitcast i8* %12 to [8 x i8]*
  %14 = bitcast i64* %"@bar_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %14)
  store i64 0, i64* %"@bar_key", align 8
  %pseudo3 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem4 = call i64 inttoptr (i64 2 to i64 (i64, i64*, [8 x i8]*, i64)*)(i64 %pseudo3, i64* %"@bar_key", [8 x i8]* %13, i64 0)
  %15 = bitcast i64* %"@bar_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %15)
  %16 = bitcast [16 x i8]* %lookup_elem_val to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %16)
  %17 = bitcast i64* %"@foo_key5" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %17)
  store i64 0, i64* %"@foo_key5", align 8
  %pseudo6 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem7 = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo6, i64* %"@foo_key5")
  %18 = bitcast [16 x i8]* %lookup_elem_val11 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %18)
  %map_lookup_cond12 = icmp ne i8* %lookup_elem7, null
  br i1 %map_lookup_cond12, label %lookup_success8, label %lookup_failure9

lookup_success8:                                  ; preds = %lookup_merge
  %19 = bitcast [16 x i8]* %lookup_elem_val11 to i8*
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* align 1 %19, i8* align 1 %lookup_elem7, i64 16, i1 false)
  br label %lookup_merge10

lookup_failure9:                                  ; preds = %lookup_merge
  %20 = bitcast [16 x i8]* %lookup_elem_val11 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %20, i8 0, i64 16, i1 false)
  br label %lookup_merge10

lookup_merge10:                                   ; preds = %lookup_failure9, %lookup_success8
  %21 = bitcast i64* %"@foo_key5" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %21)
  %22 = getelementptr [16 x i8], [16 x i8]* %lookup_elem_val11, i32 0, i64 4
  %23 = bitcast i8* %22 to [8 x i8]*
  %24 = getelementptr [8 x i8], [8 x i8]* %23, i32 0, i64 0
  %25 = bitcast i8* %24 to i32*
  %26 = load volatile i32, i32* %25, align 4
  %27 = bitcast [16 x i8]* %lookup_elem_val11 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %27)
  %28 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %28)
  store i64 0, i64* %"@x_key", align 8
  %29 = sext i32 %26 to i64
  %30 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %30)
  store i64 %29, i64* %"@x_val", align 8
  %pseudo13 = call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  %update_elem14 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo13, i64* %"@x_key", i64* %"@x_val", i64 0)
  %31 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %31)
  %32 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %32)
  ret i64 0
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.memcpy.p0i8.p0i8.i64(i8* noalias nocapture writeonly %0, i8* noalias nocapture readonly %1, i64 %2, i1 immarg %3) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn writeonly
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }
attributes #2 = { argmemonly nofree nosync nounwind willreturn writeonly }
