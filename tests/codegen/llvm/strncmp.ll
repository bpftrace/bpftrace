; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"tracepoint:file:filename"(i8* %0) section "s_tracepoint:file:filename_1" {
entry:
  %"@_val" = alloca i64, align 8
  %"@_key" = alloca i64, align 8
  %strcmp.result = alloca i1, align 1
  %comm = alloca [16 x i8], align 1
  %str = alloca [64 x i8], align 1
  %strlen = alloca i64, align 8
  %1 = bitcast i64* %strlen to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  %2 = bitcast i64* %strlen to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %2, i8 0, i64 8, i1 false)
  store i64 64, i64* %strlen, align 8
  %3 = bitcast [64 x i8]* %str to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %3)
  %4 = bitcast [64 x i8]* %str to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %4, i8 0, i64 64, i1 false)
  %5 = ptrtoint i8* %0 to i64
  %6 = add i64 %5, 8
  %7 = inttoptr i64 %6 to i64*
  %8 = load volatile i64, i64* %7, align 8
  %9 = load i64, i64* %strlen, align 8
  %10 = trunc i64 %9 to i32
  %probe_read_kernel_str = call i64 inttoptr (i64 115 to i64 ([64 x i8]*, i32, i64)*)([64 x i8]* %str, i32 %10, i64 %8)
  %11 = bitcast i64* %strlen to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %11)
  %12 = bitcast [16 x i8]* %comm to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %12)
  %13 = bitcast [16 x i8]* %comm to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %13, i8 0, i64 16, i1 false)
  %get_comm = call i64 inttoptr (i64 16 to i64 ([16 x i8]*, i64)*)([16 x i8]* %comm, i64 16)
  %14 = bitcast i1* %strcmp.result to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %14)
  store i1 false, i1* %strcmp.result, align 1
  %15 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 0
  %16 = load i8, i8* %15, align 1
  %17 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 0
  %18 = load i8, i8* %17, align 1
  %strcmp.cmp = icmp ne i8 %16, %18
  br i1 %strcmp.cmp, label %strcmp.false, label %strcmp.loop_null_cmp

pred_false:                                       ; preds = %strcmp.false
  ret i64 1

pred_true:                                        ; preds = %strcmp.false
  %19 = bitcast [16 x i8]* %comm to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %19)
  %20 = bitcast i64* %"@_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %20)
  store i64 0, i64* %"@_key", align 8
  %21 = bitcast i64* %"@_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %21)
  store i64 1, i64* %"@_val", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo, i64* %"@_key", i64* %"@_val", i64 0)
  %22 = bitcast i64* %"@_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %22)
  %23 = bitcast i64* %"@_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %23)
  ret i64 1

strcmp.false:                                     ; preds = %strcmp.done, %strcmp.loop53, %strcmp.loop49, %strcmp.loop45, %strcmp.loop41, %strcmp.loop37, %strcmp.loop33, %strcmp.loop29, %strcmp.loop25, %strcmp.loop21, %strcmp.loop17, %strcmp.loop13, %strcmp.loop9, %strcmp.loop5, %strcmp.loop1, %strcmp.loop, %entry
  %24 = load i1, i1* %strcmp.result, align 1
  %25 = bitcast i1* %strcmp.result to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %25)
  %26 = zext i1 %24 to i64
  %predcond = icmp eq i64 %26, 0
  br i1 %predcond, label %pred_false, label %pred_true

strcmp.done:                                      ; preds = %strcmp.loop57, %strcmp.loop_null_cmp58, %strcmp.loop_null_cmp54, %strcmp.loop_null_cmp50, %strcmp.loop_null_cmp46, %strcmp.loop_null_cmp42, %strcmp.loop_null_cmp38, %strcmp.loop_null_cmp34, %strcmp.loop_null_cmp30, %strcmp.loop_null_cmp26, %strcmp.loop_null_cmp22, %strcmp.loop_null_cmp18, %strcmp.loop_null_cmp14, %strcmp.loop_null_cmp10, %strcmp.loop_null_cmp6, %strcmp.loop_null_cmp2, %strcmp.loop_null_cmp
  store i1 true, i1* %strcmp.result, align 1
  br label %strcmp.false

strcmp.loop:                                      ; preds = %strcmp.loop_null_cmp
  %27 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 1
  %28 = load i8, i8* %27, align 1
  %29 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 1
  %30 = load i8, i8* %29, align 1
  %strcmp.cmp3 = icmp ne i8 %28, %30
  br i1 %strcmp.cmp3, label %strcmp.false, label %strcmp.loop_null_cmp2

strcmp.loop_null_cmp:                             ; preds = %entry
  %strcmp.cmp_null = icmp eq i8 %16, 0
  br i1 %strcmp.cmp_null, label %strcmp.done, label %strcmp.loop

strcmp.loop1:                                     ; preds = %strcmp.loop_null_cmp2
  %31 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 2
  %32 = load i8, i8* %31, align 1
  %33 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 2
  %34 = load i8, i8* %33, align 1
  %strcmp.cmp7 = icmp ne i8 %32, %34
  br i1 %strcmp.cmp7, label %strcmp.false, label %strcmp.loop_null_cmp6

strcmp.loop_null_cmp2:                            ; preds = %strcmp.loop
  %strcmp.cmp_null4 = icmp eq i8 %28, 0
  br i1 %strcmp.cmp_null4, label %strcmp.done, label %strcmp.loop1

strcmp.loop5:                                     ; preds = %strcmp.loop_null_cmp6
  %35 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 3
  %36 = load i8, i8* %35, align 1
  %37 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 3
  %38 = load i8, i8* %37, align 1
  %strcmp.cmp11 = icmp ne i8 %36, %38
  br i1 %strcmp.cmp11, label %strcmp.false, label %strcmp.loop_null_cmp10

strcmp.loop_null_cmp6:                            ; preds = %strcmp.loop1
  %strcmp.cmp_null8 = icmp eq i8 %32, 0
  br i1 %strcmp.cmp_null8, label %strcmp.done, label %strcmp.loop5

strcmp.loop9:                                     ; preds = %strcmp.loop_null_cmp10
  %39 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 4
  %40 = load i8, i8* %39, align 1
  %41 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 4
  %42 = load i8, i8* %41, align 1
  %strcmp.cmp15 = icmp ne i8 %40, %42
  br i1 %strcmp.cmp15, label %strcmp.false, label %strcmp.loop_null_cmp14

strcmp.loop_null_cmp10:                           ; preds = %strcmp.loop5
  %strcmp.cmp_null12 = icmp eq i8 %36, 0
  br i1 %strcmp.cmp_null12, label %strcmp.done, label %strcmp.loop9

strcmp.loop13:                                    ; preds = %strcmp.loop_null_cmp14
  %43 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 5
  %44 = load i8, i8* %43, align 1
  %45 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 5
  %46 = load i8, i8* %45, align 1
  %strcmp.cmp19 = icmp ne i8 %44, %46
  br i1 %strcmp.cmp19, label %strcmp.false, label %strcmp.loop_null_cmp18

strcmp.loop_null_cmp14:                           ; preds = %strcmp.loop9
  %strcmp.cmp_null16 = icmp eq i8 %40, 0
  br i1 %strcmp.cmp_null16, label %strcmp.done, label %strcmp.loop13

strcmp.loop17:                                    ; preds = %strcmp.loop_null_cmp18
  %47 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 6
  %48 = load i8, i8* %47, align 1
  %49 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 6
  %50 = load i8, i8* %49, align 1
  %strcmp.cmp23 = icmp ne i8 %48, %50
  br i1 %strcmp.cmp23, label %strcmp.false, label %strcmp.loop_null_cmp22

strcmp.loop_null_cmp18:                           ; preds = %strcmp.loop13
  %strcmp.cmp_null20 = icmp eq i8 %44, 0
  br i1 %strcmp.cmp_null20, label %strcmp.done, label %strcmp.loop17

strcmp.loop21:                                    ; preds = %strcmp.loop_null_cmp22
  %51 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 7
  %52 = load i8, i8* %51, align 1
  %53 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 7
  %54 = load i8, i8* %53, align 1
  %strcmp.cmp27 = icmp ne i8 %52, %54
  br i1 %strcmp.cmp27, label %strcmp.false, label %strcmp.loop_null_cmp26

strcmp.loop_null_cmp22:                           ; preds = %strcmp.loop17
  %strcmp.cmp_null24 = icmp eq i8 %48, 0
  br i1 %strcmp.cmp_null24, label %strcmp.done, label %strcmp.loop21

strcmp.loop25:                                    ; preds = %strcmp.loop_null_cmp26
  %55 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 8
  %56 = load i8, i8* %55, align 1
  %57 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 8
  %58 = load i8, i8* %57, align 1
  %strcmp.cmp31 = icmp ne i8 %56, %58
  br i1 %strcmp.cmp31, label %strcmp.false, label %strcmp.loop_null_cmp30

strcmp.loop_null_cmp26:                           ; preds = %strcmp.loop21
  %strcmp.cmp_null28 = icmp eq i8 %52, 0
  br i1 %strcmp.cmp_null28, label %strcmp.done, label %strcmp.loop25

strcmp.loop29:                                    ; preds = %strcmp.loop_null_cmp30
  %59 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 9
  %60 = load i8, i8* %59, align 1
  %61 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 9
  %62 = load i8, i8* %61, align 1
  %strcmp.cmp35 = icmp ne i8 %60, %62
  br i1 %strcmp.cmp35, label %strcmp.false, label %strcmp.loop_null_cmp34

strcmp.loop_null_cmp30:                           ; preds = %strcmp.loop25
  %strcmp.cmp_null32 = icmp eq i8 %56, 0
  br i1 %strcmp.cmp_null32, label %strcmp.done, label %strcmp.loop29

strcmp.loop33:                                    ; preds = %strcmp.loop_null_cmp34
  %63 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 10
  %64 = load i8, i8* %63, align 1
  %65 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 10
  %66 = load i8, i8* %65, align 1
  %strcmp.cmp39 = icmp ne i8 %64, %66
  br i1 %strcmp.cmp39, label %strcmp.false, label %strcmp.loop_null_cmp38

strcmp.loop_null_cmp34:                           ; preds = %strcmp.loop29
  %strcmp.cmp_null36 = icmp eq i8 %60, 0
  br i1 %strcmp.cmp_null36, label %strcmp.done, label %strcmp.loop33

strcmp.loop37:                                    ; preds = %strcmp.loop_null_cmp38
  %67 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 11
  %68 = load i8, i8* %67, align 1
  %69 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 11
  %70 = load i8, i8* %69, align 1
  %strcmp.cmp43 = icmp ne i8 %68, %70
  br i1 %strcmp.cmp43, label %strcmp.false, label %strcmp.loop_null_cmp42

strcmp.loop_null_cmp38:                           ; preds = %strcmp.loop33
  %strcmp.cmp_null40 = icmp eq i8 %64, 0
  br i1 %strcmp.cmp_null40, label %strcmp.done, label %strcmp.loop37

strcmp.loop41:                                    ; preds = %strcmp.loop_null_cmp42
  %71 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 12
  %72 = load i8, i8* %71, align 1
  %73 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 12
  %74 = load i8, i8* %73, align 1
  %strcmp.cmp47 = icmp ne i8 %72, %74
  br i1 %strcmp.cmp47, label %strcmp.false, label %strcmp.loop_null_cmp46

strcmp.loop_null_cmp42:                           ; preds = %strcmp.loop37
  %strcmp.cmp_null44 = icmp eq i8 %68, 0
  br i1 %strcmp.cmp_null44, label %strcmp.done, label %strcmp.loop41

strcmp.loop45:                                    ; preds = %strcmp.loop_null_cmp46
  %75 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 13
  %76 = load i8, i8* %75, align 1
  %77 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 13
  %78 = load i8, i8* %77, align 1
  %strcmp.cmp51 = icmp ne i8 %76, %78
  br i1 %strcmp.cmp51, label %strcmp.false, label %strcmp.loop_null_cmp50

strcmp.loop_null_cmp46:                           ; preds = %strcmp.loop41
  %strcmp.cmp_null48 = icmp eq i8 %72, 0
  br i1 %strcmp.cmp_null48, label %strcmp.done, label %strcmp.loop45

strcmp.loop49:                                    ; preds = %strcmp.loop_null_cmp50
  %79 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 14
  %80 = load i8, i8* %79, align 1
  %81 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 14
  %82 = load i8, i8* %81, align 1
  %strcmp.cmp55 = icmp ne i8 %80, %82
  br i1 %strcmp.cmp55, label %strcmp.false, label %strcmp.loop_null_cmp54

strcmp.loop_null_cmp50:                           ; preds = %strcmp.loop45
  %strcmp.cmp_null52 = icmp eq i8 %76, 0
  br i1 %strcmp.cmp_null52, label %strcmp.done, label %strcmp.loop49

strcmp.loop53:                                    ; preds = %strcmp.loop_null_cmp54
  %83 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 15
  %84 = load i8, i8* %83, align 1
  %85 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 15
  %86 = load i8, i8* %85, align 1
  %strcmp.cmp59 = icmp ne i8 %84, %86
  br i1 %strcmp.cmp59, label %strcmp.false, label %strcmp.loop_null_cmp58

strcmp.loop_null_cmp54:                           ; preds = %strcmp.loop49
  %strcmp.cmp_null56 = icmp eq i8 %80, 0
  br i1 %strcmp.cmp_null56, label %strcmp.done, label %strcmp.loop53

strcmp.loop57:                                    ; preds = %strcmp.loop_null_cmp58
  br label %strcmp.done

strcmp.loop_null_cmp58:                           ; preds = %strcmp.loop53
  %strcmp.cmp_null60 = icmp eq i8 %84, 0
  br i1 %strcmp.cmp_null60, label %strcmp.done, label %strcmp.loop57
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
