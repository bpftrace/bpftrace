; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"kretprobe:vfs_read"(i8* %0) section "s_kretprobe:vfs_read_1" {
entry:
  %initial_value = alloca i64, align 8
  %comm5 = alloca [16 x i8], align 1
  %strcmp.result = alloca i1, align 1
  %comm = alloca [16 x i8], align 1
  %1 = bitcast [16 x i8]* %comm to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  %2 = bitcast [16 x i8]* %comm to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %2, i8 0, i64 16, i1 false)
  %get_comm = call i64 inttoptr (i64 16 to i64 ([16 x i8]*, i64)*)([16 x i8]* %comm, i64 16)
  %3 = bitcast i1* %strcmp.result to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %3)
  store i1 true, i1* %strcmp.result, align 1
  %4 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 0
  %5 = load i8, i8* %4, align 1
  %strcmp.cmp = icmp ne i8 %5, 115
  br i1 %strcmp.cmp, label %strcmp.false, label %strcmp.loop_null_cmp

pred_false:                                       ; preds = %strcmp.false
  ret i64 0

pred_true:                                        ; preds = %strcmp.false
  %6 = bitcast [16 x i8]* %comm to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %6)
  %7 = bitcast [16 x i8]* %comm5 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %7)
  %8 = bitcast [16 x i8]* %comm5 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %8, i8 0, i64 16, i1 false)
  %get_comm6 = call i64 inttoptr (i64 16 to i64 ([16 x i8]*, i64)*)([16 x i8]* %comm5, i64 16)
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i64, [16 x i8]*)*)(i64 %pseudo, [16 x i8]* %comm5)
  %cast = bitcast i8* %lookup_elem to i64*
  %9 = icmp eq i64* %cast, null
  br i1 %9, label %ptr_null, label %ptr_merge

strcmp.false:                                     ; preds = %strcmp.done, %strcmp.loop, %entry
  %10 = load i1, i1* %strcmp.result, align 1
  %11 = bitcast i1* %strcmp.result to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %11)
  %12 = zext i1 %10 to i64
  %predcond = icmp eq i64 %12, 0
  br i1 %predcond, label %pred_false, label %pred_true

strcmp.done:                                      ; preds = %strcmp.loop1, %strcmp.loop_null_cmp2, %strcmp.loop_null_cmp
  store i1 false, i1* %strcmp.result, align 1
  br label %strcmp.false

strcmp.loop:                                      ; preds = %strcmp.loop_null_cmp
  %13 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 1
  %14 = load i8, i8* %13, align 1
  %strcmp.cmp3 = icmp ne i8 %14, 115
  br i1 %strcmp.cmp3, label %strcmp.false, label %strcmp.loop_null_cmp2

strcmp.loop_null_cmp:                             ; preds = %entry
  %strcmp.cmp_null = icmp eq i8 %5, 0
  br i1 %strcmp.cmp_null, label %strcmp.done, label %strcmp.loop

strcmp.loop1:                                     ; preds = %strcmp.loop_null_cmp2
  br label %strcmp.done

strcmp.loop_null_cmp2:                            ; preds = %strcmp.loop
  %strcmp.cmp_null4 = icmp eq i8 %14, 0
  br i1 %strcmp.cmp_null4, label %strcmp.done, label %strcmp.loop1

ptr_null:                                         ; preds = %pred_true
  %15 = bitcast i64* %initial_value to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %15)
  store i64 0, i64* %initial_value, align 8
  %pseudo7 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, [16 x i8]*, i64*, i64)*)(i64 %pseudo7, [16 x i8]* %comm5, i64* %initial_value, i64 0)
  %pseudo8 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %lookup_elem9 = call i8* inttoptr (i64 1 to i8* (i64, [16 x i8]*)*)(i64 %pseudo8, [16 x i8]* %comm5)
  %cast10 = bitcast i8* %lookup_elem9 to i64*
  %16 = bitcast i64* %initial_value to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %16)
  br label %ptr_merge

ptr_merge:                                        ; preds = %ptr_null, %pred_true
  %17 = icmp ne i64* %cast10, null
  br i1 %17, label %ptr_not_null, label %merge

ptr_not_null:                                     ; preds = %ptr_merge
  %18 = load i64, i64* %cast10, align 8
  %19 = add i64 %18, 1
  store i64 %19, i64* %cast10, align 8
  br label %merge

merge:                                            ; preds = %ptr_not_null, %ptr_merge
  %20 = bitcast [16 x i8]* %comm5 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %20)
  ret i64 0
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn writeonly
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }
attributes #2 = { argmemonly nofree nosync nounwind willreturn writeonly }
