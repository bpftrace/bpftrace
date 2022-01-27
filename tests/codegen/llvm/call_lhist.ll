; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"kprobe:f"(i8* %0) section "s_kprobe:f_1" {
entry:
  %"@x_val" = alloca i64, align 8
  %lookup_elem_val = alloca i64, align 8
  %"@x_key8" = alloca i64, align 8
  %"@x_step" = alloca i64, align 8
  %"@x_key5" = alloca i64, align 8
  %"@x_max" = alloca i64, align 8
  %"@x_key2" = alloca i64, align 8
  %"@x_min" = alloca i64, align 8
  %"@x_key" = alloca i64, align 8
  %get_pid_tgid = call i64 inttoptr (i64 14 to i64 ()*)()
  %1 = lshr i64 %get_pid_tgid, 32
  %get_pid_tgid1 = call i64 inttoptr (i64 14 to i64 ()*)()
  %2 = lshr i64 %get_pid_tgid1, 32
  %linear = call i64 @linear(i64 %2, i64 0, i64 100, i64 1)
  %3 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %3)
  store i64 -1, i64* %"@x_key", align 8
  %4 = bitcast i64* %"@x_min" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %4)
  store i64 0, i64* %"@x_min", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo, i64* %"@x_key", i64* %"@x_min", i64 0)
  %5 = bitcast i64* %"@x_min" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %5)
  %6 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %6)
  %7 = bitcast i64* %"@x_key2" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %7)
  store i64 -2, i64* %"@x_key2", align 8
  %8 = bitcast i64* %"@x_max" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %8)
  store i64 100, i64* %"@x_max", align 8
  %pseudo3 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem4 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo3, i64* %"@x_key2", i64* %"@x_max", i64 0)
  %9 = bitcast i64* %"@x_max" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %9)
  %10 = bitcast i64* %"@x_key2" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %10)
  %11 = bitcast i64* %"@x_key5" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %11)
  store i64 -3, i64* %"@x_key5", align 8
  %12 = bitcast i64* %"@x_step" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %12)
  store i64 1, i64* %"@x_step", align 8
  %pseudo6 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem7 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo6, i64* %"@x_key5", i64* %"@x_step", i64 0)
  %13 = bitcast i64* %"@x_step" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %13)
  %14 = bitcast i64* %"@x_key5" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %14)
  %15 = bitcast i64* %"@x_key8" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %15)
  store i64 %linear, i64* %"@x_key8", align 8
  %pseudo9 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo9, i64* %"@x_key8")
  %16 = bitcast i64* %lookup_elem_val to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %16)
  %map_lookup_cond = icmp ne i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  %cast = bitcast i8* %lookup_elem to i64*
  %17 = load i64, i64* %cast, align 8
  store i64 %17, i64* %lookup_elem_val, align 8
  br label %lookup_merge

lookup_failure:                                   ; preds = %entry
  store i64 0, i64* %lookup_elem_val, align 8
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  %18 = load i64, i64* %lookup_elem_val, align 8
  %19 = bitcast i64* %lookup_elem_val to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %19)
  %20 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %20)
  %21 = add i64 %18, 1
  store i64 %21, i64* %"@x_val", align 8
  %pseudo10 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem11 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo10, i64* %"@x_key8", i64* %"@x_val", i64 0)
  %22 = bitcast i64* %"@x_key8" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %22)
  %23 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %23)
  ret i64 0
}

; Function Attrs: alwaysinline
define internal i64 @linear(i64 %0, i64 %1, i64 %2, i64 %3) #1 section "helpers" {
entry:
  %4 = alloca i64, align 8
  %5 = alloca i64, align 8
  %6 = alloca i64, align 8
  %7 = alloca i64, align 8
  %8 = alloca i64, align 8
  %9 = bitcast i64* %8 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %9)
  %10 = bitcast i64* %7 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %10)
  %11 = bitcast i64* %6 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %11)
  %12 = bitcast i64* %5 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %12)
  %13 = bitcast i64* %4 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %13)
  store i64 %0, i64* %8, align 8
  store i64 %1, i64* %7, align 8
  store i64 %2, i64* %6, align 8
  store i64 %3, i64* %5, align 8
  %14 = load i64, i64* %7, align 8
  %15 = load i64, i64* %8, align 8
  %16 = icmp slt i64 %15, %14
  br i1 %16, label %lhist.lt_min, label %lhist.ge_min

lhist.lt_min:                                     ; preds = %entry
  ret i64 0

lhist.ge_min:                                     ; preds = %entry
  %17 = load i64, i64* %6, align 8
  %18 = load i64, i64* %8, align 8
  %19 = icmp sgt i64 %18, %17
  br i1 %19, label %lhist.gt_max, label %lhist.le_max

lhist.le_max:                                     ; preds = %lhist.ge_min
  %20 = load i64, i64* %5, align 8
  %21 = load i64, i64* %7, align 8
  %22 = load i64, i64* %8, align 8
  %23 = sub i64 %22, %21
  %24 = udiv i64 %23, %20
  %25 = add i64 %24, 1
  store i64 %25, i64* %4, align 8
  %26 = load i64, i64* %4, align 8
  ret i64 %26

lhist.gt_max:                                     ; preds = %lhist.ge_min
  %27 = load i64, i64* %5, align 8
  %28 = load i64, i64* %7, align 8
  %29 = load i64, i64* %6, align 8
  %30 = sub i64 %29, %28
  %31 = udiv i64 %30, %27
  %32 = add i64 %31, 1
  store i64 %32, i64* %4, align 8
  %33 = load i64, i64* %4, align 8
  ret i64 %33
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #2

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #2

attributes #0 = { nounwind }
attributes #1 = { alwaysinline }
attributes #2 = { argmemonly nofree nosync nounwind willreturn }
