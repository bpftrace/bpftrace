; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

define i64 @"tracepoint:file:filename"(i8*) section "s_tracepoint:file:filename_1" {
entry:
  %"@_val" = alloca i64
  %"@_key" = alloca i64
  %strcmp.char_r = alloca i8
  %strcmp.char_l = alloca i8
  %strcmp.result = alloca i1
  %str = alloca [64 x i8]
  %strlen = alloca i64
  %comm = alloca [16 x i8]
  %1 = bitcast [16 x i8]* %comm to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  %2 = bitcast [16 x i8]* %comm to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %2, i8 0, i64 16, i1 false)
  %get_comm = call i64 inttoptr (i64 16 to i64 ([16 x i8]*, i64)*)([16 x i8]* %comm, i64 16)
  %3 = bitcast i64* %strlen to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %3)
  %4 = bitcast i64* %strlen to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %4, i8 0, i64 8, i1 false)
  store i64 64, i64* %strlen
  %5 = bitcast [64 x i8]* %str to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %5)
  %6 = bitcast [64 x i8]* %str to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %6, i8 0, i64 64, i1 false)
  %7 = ptrtoint i8* %0 to i64
  %8 = add i64 %7, 8
  %9 = inttoptr i64 %8 to i64*
  %10 = load volatile i64, i64* %9
  %11 = load i64, i64* %strlen
  %12 = trunc i64 %11 to i32
  %probe_read_kernel_str = call i64 inttoptr (i64 115 to i64 ([64 x i8]*, i32, i64)*)([64 x i8]* %str, i32 %12, i64 %10)
  %13 = icmp sgt i64 %probe_read_kernel_str, 0
  br i1 %13, label %str_success, label %str_merge

pred_false:                                       ; preds = %strcmp.false
  ret i64 0

pred_true:                                        ; preds = %strcmp.false
  %14 = bitcast i64* %"@_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %14)
  store i64 0, i64* %"@_key"
  %15 = bitcast i64* %"@_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %15)
  store i64 1, i64* %"@_val"
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo, i64* %"@_key", i64* %"@_val", i64 0)
  %16 = bitcast i64* %"@_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %16)
  %17 = bitcast i64* %"@_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %17)
  ret i64 0

str_success:                                      ; preds = %entry
  %18 = bitcast [64 x i8]* %str to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %18, i8 0, i64 64, i1 false)
  %19 = and i64 %probe_read_kernel_str, 63
  %20 = trunc i64 %19 to i32
  %probe_read_kernel = call i64 inttoptr (i64 113 to i64 ([64 x i8]*, i32, i64)*)([64 x i8]* %str, i32 %20, i64 %10)
  br label %str_merge

str_merge:                                        ; preds = %str_success, %entry
  %21 = bitcast i64* %strlen to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %21)
  %22 = bitcast i1* %strcmp.result to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %22)
  store i1 false, i1* %strcmp.result
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %strcmp.char_l)
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %strcmp.char_r)
  %23 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 0
  %probe_read_kernel1 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %23)
  %24 = load i8, i8* %strcmp.char_l
  %25 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 0
  %probe_read_kernel2 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %25)
  %26 = load i8, i8* %strcmp.char_r
  %strcmp.cmp = icmp ne i8 %24, %26
  br i1 %strcmp.cmp, label %strcmp.false, label %strcmp.loop_null_cmp

strcmp.false:                                     ; preds = %strcmp.done, %strcmp.loop87, %strcmp.loop81, %strcmp.loop75, %strcmp.loop69, %strcmp.loop63, %strcmp.loop57, %strcmp.loop51, %strcmp.loop45, %strcmp.loop39, %strcmp.loop33, %strcmp.loop27, %strcmp.loop21, %strcmp.loop15, %strcmp.loop9, %strcmp.loop3, %strcmp.loop, %str_merge
  %27 = load i1, i1* %strcmp.result
  %28 = bitcast i1* %strcmp.result to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %28)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %strcmp.char_l)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %strcmp.char_r)
  %29 = zext i1 %27 to i64
  %30 = bitcast [64 x i8]* %str to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %30)
  %31 = bitcast [16 x i8]* %comm to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %31)
  %predcond = icmp eq i64 %29, 0
  br i1 %predcond, label %pred_false, label %pred_true

strcmp.done:                                      ; preds = %strcmp.loop93, %strcmp.loop_null_cmp94, %strcmp.loop_null_cmp88, %strcmp.loop_null_cmp82, %strcmp.loop_null_cmp76, %strcmp.loop_null_cmp70, %strcmp.loop_null_cmp64, %strcmp.loop_null_cmp58, %strcmp.loop_null_cmp52, %strcmp.loop_null_cmp46, %strcmp.loop_null_cmp40, %strcmp.loop_null_cmp34, %strcmp.loop_null_cmp28, %strcmp.loop_null_cmp22, %strcmp.loop_null_cmp16, %strcmp.loop_null_cmp10, %strcmp.loop_null_cmp4, %strcmp.loop_null_cmp
  store i1 true, i1* %strcmp.result
  br label %strcmp.false

strcmp.loop:                                      ; preds = %strcmp.loop_null_cmp
  %32 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 1
  %probe_read_kernel5 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %32)
  %33 = load i8, i8* %strcmp.char_l
  %34 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 1
  %probe_read_kernel6 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %34)
  %35 = load i8, i8* %strcmp.char_r
  %strcmp.cmp7 = icmp ne i8 %33, %35
  br i1 %strcmp.cmp7, label %strcmp.false, label %strcmp.loop_null_cmp4

strcmp.loop_null_cmp:                             ; preds = %str_merge
  %strcmp.cmp_null = icmp eq i8 %24, 0
  br i1 %strcmp.cmp_null, label %strcmp.done, label %strcmp.loop

strcmp.loop3:                                     ; preds = %strcmp.loop_null_cmp4
  %36 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 2
  %probe_read_kernel11 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %36)
  %37 = load i8, i8* %strcmp.char_l
  %38 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 2
  %probe_read_kernel12 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %38)
  %39 = load i8, i8* %strcmp.char_r
  %strcmp.cmp13 = icmp ne i8 %37, %39
  br i1 %strcmp.cmp13, label %strcmp.false, label %strcmp.loop_null_cmp10

strcmp.loop_null_cmp4:                            ; preds = %strcmp.loop
  %strcmp.cmp_null8 = icmp eq i8 %33, 0
  br i1 %strcmp.cmp_null8, label %strcmp.done, label %strcmp.loop3

strcmp.loop9:                                     ; preds = %strcmp.loop_null_cmp10
  %40 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 3
  %probe_read_kernel17 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %40)
  %41 = load i8, i8* %strcmp.char_l
  %42 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 3
  %probe_read_kernel18 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %42)
  %43 = load i8, i8* %strcmp.char_r
  %strcmp.cmp19 = icmp ne i8 %41, %43
  br i1 %strcmp.cmp19, label %strcmp.false, label %strcmp.loop_null_cmp16

strcmp.loop_null_cmp10:                           ; preds = %strcmp.loop3
  %strcmp.cmp_null14 = icmp eq i8 %37, 0
  br i1 %strcmp.cmp_null14, label %strcmp.done, label %strcmp.loop9

strcmp.loop15:                                    ; preds = %strcmp.loop_null_cmp16
  %44 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 4
  %probe_read_kernel23 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %44)
  %45 = load i8, i8* %strcmp.char_l
  %46 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 4
  %probe_read_kernel24 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %46)
  %47 = load i8, i8* %strcmp.char_r
  %strcmp.cmp25 = icmp ne i8 %45, %47
  br i1 %strcmp.cmp25, label %strcmp.false, label %strcmp.loop_null_cmp22

strcmp.loop_null_cmp16:                           ; preds = %strcmp.loop9
  %strcmp.cmp_null20 = icmp eq i8 %41, 0
  br i1 %strcmp.cmp_null20, label %strcmp.done, label %strcmp.loop15

strcmp.loop21:                                    ; preds = %strcmp.loop_null_cmp22
  %48 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 5
  %probe_read_kernel29 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %48)
  %49 = load i8, i8* %strcmp.char_l
  %50 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 5
  %probe_read_kernel30 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %50)
  %51 = load i8, i8* %strcmp.char_r
  %strcmp.cmp31 = icmp ne i8 %49, %51
  br i1 %strcmp.cmp31, label %strcmp.false, label %strcmp.loop_null_cmp28

strcmp.loop_null_cmp22:                           ; preds = %strcmp.loop15
  %strcmp.cmp_null26 = icmp eq i8 %45, 0
  br i1 %strcmp.cmp_null26, label %strcmp.done, label %strcmp.loop21

strcmp.loop27:                                    ; preds = %strcmp.loop_null_cmp28
  %52 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 6
  %probe_read_kernel35 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %52)
  %53 = load i8, i8* %strcmp.char_l
  %54 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 6
  %probe_read_kernel36 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %54)
  %55 = load i8, i8* %strcmp.char_r
  %strcmp.cmp37 = icmp ne i8 %53, %55
  br i1 %strcmp.cmp37, label %strcmp.false, label %strcmp.loop_null_cmp34

strcmp.loop_null_cmp28:                           ; preds = %strcmp.loop21
  %strcmp.cmp_null32 = icmp eq i8 %49, 0
  br i1 %strcmp.cmp_null32, label %strcmp.done, label %strcmp.loop27

strcmp.loop33:                                    ; preds = %strcmp.loop_null_cmp34
  %56 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 7
  %probe_read_kernel41 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %56)
  %57 = load i8, i8* %strcmp.char_l
  %58 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 7
  %probe_read_kernel42 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %58)
  %59 = load i8, i8* %strcmp.char_r
  %strcmp.cmp43 = icmp ne i8 %57, %59
  br i1 %strcmp.cmp43, label %strcmp.false, label %strcmp.loop_null_cmp40

strcmp.loop_null_cmp34:                           ; preds = %strcmp.loop27
  %strcmp.cmp_null38 = icmp eq i8 %53, 0
  br i1 %strcmp.cmp_null38, label %strcmp.done, label %strcmp.loop33

strcmp.loop39:                                    ; preds = %strcmp.loop_null_cmp40
  %60 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 8
  %probe_read_kernel47 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %60)
  %61 = load i8, i8* %strcmp.char_l
  %62 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 8
  %probe_read_kernel48 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %62)
  %63 = load i8, i8* %strcmp.char_r
  %strcmp.cmp49 = icmp ne i8 %61, %63
  br i1 %strcmp.cmp49, label %strcmp.false, label %strcmp.loop_null_cmp46

strcmp.loop_null_cmp40:                           ; preds = %strcmp.loop33
  %strcmp.cmp_null44 = icmp eq i8 %57, 0
  br i1 %strcmp.cmp_null44, label %strcmp.done, label %strcmp.loop39

strcmp.loop45:                                    ; preds = %strcmp.loop_null_cmp46
  %64 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 9
  %probe_read_kernel53 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %64)
  %65 = load i8, i8* %strcmp.char_l
  %66 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 9
  %probe_read_kernel54 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %66)
  %67 = load i8, i8* %strcmp.char_r
  %strcmp.cmp55 = icmp ne i8 %65, %67
  br i1 %strcmp.cmp55, label %strcmp.false, label %strcmp.loop_null_cmp52

strcmp.loop_null_cmp46:                           ; preds = %strcmp.loop39
  %strcmp.cmp_null50 = icmp eq i8 %61, 0
  br i1 %strcmp.cmp_null50, label %strcmp.done, label %strcmp.loop45

strcmp.loop51:                                    ; preds = %strcmp.loop_null_cmp52
  %68 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 10
  %probe_read_kernel59 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %68)
  %69 = load i8, i8* %strcmp.char_l
  %70 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 10
  %probe_read_kernel60 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %70)
  %71 = load i8, i8* %strcmp.char_r
  %strcmp.cmp61 = icmp ne i8 %69, %71
  br i1 %strcmp.cmp61, label %strcmp.false, label %strcmp.loop_null_cmp58

strcmp.loop_null_cmp52:                           ; preds = %strcmp.loop45
  %strcmp.cmp_null56 = icmp eq i8 %65, 0
  br i1 %strcmp.cmp_null56, label %strcmp.done, label %strcmp.loop51

strcmp.loop57:                                    ; preds = %strcmp.loop_null_cmp58
  %72 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 11
  %probe_read_kernel65 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %72)
  %73 = load i8, i8* %strcmp.char_l
  %74 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 11
  %probe_read_kernel66 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %74)
  %75 = load i8, i8* %strcmp.char_r
  %strcmp.cmp67 = icmp ne i8 %73, %75
  br i1 %strcmp.cmp67, label %strcmp.false, label %strcmp.loop_null_cmp64

strcmp.loop_null_cmp58:                           ; preds = %strcmp.loop51
  %strcmp.cmp_null62 = icmp eq i8 %69, 0
  br i1 %strcmp.cmp_null62, label %strcmp.done, label %strcmp.loop57

strcmp.loop63:                                    ; preds = %strcmp.loop_null_cmp64
  %76 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 12
  %probe_read_kernel71 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %76)
  %77 = load i8, i8* %strcmp.char_l
  %78 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 12
  %probe_read_kernel72 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %78)
  %79 = load i8, i8* %strcmp.char_r
  %strcmp.cmp73 = icmp ne i8 %77, %79
  br i1 %strcmp.cmp73, label %strcmp.false, label %strcmp.loop_null_cmp70

strcmp.loop_null_cmp64:                           ; preds = %strcmp.loop57
  %strcmp.cmp_null68 = icmp eq i8 %73, 0
  br i1 %strcmp.cmp_null68, label %strcmp.done, label %strcmp.loop63

strcmp.loop69:                                    ; preds = %strcmp.loop_null_cmp70
  %80 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 13
  %probe_read_kernel77 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %80)
  %81 = load i8, i8* %strcmp.char_l
  %82 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 13
  %probe_read_kernel78 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %82)
  %83 = load i8, i8* %strcmp.char_r
  %strcmp.cmp79 = icmp ne i8 %81, %83
  br i1 %strcmp.cmp79, label %strcmp.false, label %strcmp.loop_null_cmp76

strcmp.loop_null_cmp70:                           ; preds = %strcmp.loop63
  %strcmp.cmp_null74 = icmp eq i8 %77, 0
  br i1 %strcmp.cmp_null74, label %strcmp.done, label %strcmp.loop69

strcmp.loop75:                                    ; preds = %strcmp.loop_null_cmp76
  %84 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 14
  %probe_read_kernel83 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %84)
  %85 = load i8, i8* %strcmp.char_l
  %86 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 14
  %probe_read_kernel84 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %86)
  %87 = load i8, i8* %strcmp.char_r
  %strcmp.cmp85 = icmp ne i8 %85, %87
  br i1 %strcmp.cmp85, label %strcmp.false, label %strcmp.loop_null_cmp82

strcmp.loop_null_cmp76:                           ; preds = %strcmp.loop69
  %strcmp.cmp_null80 = icmp eq i8 %81, 0
  br i1 %strcmp.cmp_null80, label %strcmp.done, label %strcmp.loop75

strcmp.loop81:                                    ; preds = %strcmp.loop_null_cmp82
  %88 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 15
  %probe_read_kernel89 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %88)
  %89 = load i8, i8* %strcmp.char_l
  %90 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 15
  %probe_read_kernel90 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %90)
  %91 = load i8, i8* %strcmp.char_r
  %strcmp.cmp91 = icmp ne i8 %89, %91
  br i1 %strcmp.cmp91, label %strcmp.false, label %strcmp.loop_null_cmp88

strcmp.loop_null_cmp82:                           ; preds = %strcmp.loop75
  %strcmp.cmp_null86 = icmp eq i8 %85, 0
  br i1 %strcmp.cmp_null86, label %strcmp.done, label %strcmp.loop81

strcmp.loop87:                                    ; preds = %strcmp.loop_null_cmp88
  %92 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 16
  %probe_read_kernel95 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %92)
  %93 = load i8, i8* %strcmp.char_l
  %94 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 16
  %probe_read_kernel96 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %94)
  %95 = load i8, i8* %strcmp.char_r
  %strcmp.cmp97 = icmp ne i8 %93, %95
  br i1 %strcmp.cmp97, label %strcmp.false, label %strcmp.loop_null_cmp94

strcmp.loop_null_cmp88:                           ; preds = %strcmp.loop81
  %strcmp.cmp_null92 = icmp eq i8 %89, 0
  br i1 %strcmp.cmp_null92, label %strcmp.done, label %strcmp.loop87

strcmp.loop93:                                    ; preds = %strcmp.loop_null_cmp94
  br label %strcmp.done

strcmp.loop_null_cmp94:                           ; preds = %strcmp.loop87
  %strcmp.cmp_null98 = icmp eq i8 %93, 0
  br i1 %strcmp.cmp_null98, label %strcmp.done, label %strcmp.loop93
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i1) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
