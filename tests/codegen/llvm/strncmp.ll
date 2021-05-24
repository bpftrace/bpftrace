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
  %strcmp.char_r = alloca i8, align 1
  %strcmp.char_l = alloca i8, align 1
  %strcmp.result = alloca i1, align 1
  %str = alloca [64 x i8], align 1
  %strlen = alloca i64, align 8
  %comm = alloca [16 x i8], align 1
  %1 = bitcast [16 x i8]* %comm to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  %2 = bitcast [16 x i8]* %comm to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %2, i8 0, i64 16, i1 false)
  %get_comm = call i64 inttoptr (i64 16 to i64 ([16 x i8]*, i64)*)([16 x i8]* %comm, i64 16)
  %3 = bitcast i64* %strlen to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %3)
  %4 = bitcast i64* %strlen to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %4, i8 0, i64 8, i1 false)
  store i64 64, i64* %strlen, align 8
  %5 = bitcast [64 x i8]* %str to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %5)
  %6 = bitcast [64 x i8]* %str to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %6, i8 0, i64 64, i1 false)
  %7 = ptrtoint i8* %0 to i64
  %8 = add i64 %7, 8
  %9 = inttoptr i64 %8 to i64*
  %10 = load volatile i64, i64* %9, align 8
  %11 = load i64, i64* %strlen, align 8
  %12 = trunc i64 %11 to i32
  %probe_read_kernel_str = call i64 inttoptr (i64 115 to i64 ([64 x i8]*, i32, i64)*)([64 x i8]* %str, i32 %12, i64 %10)
  %13 = bitcast i64* %strlen to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %13)
  %14 = bitcast i1* %strcmp.result to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %14)
  store i1 false, i1* %strcmp.result, align 1
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %strcmp.char_l)
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %strcmp.char_r)
  %15 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 0
  %probe_read_kernel = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %15)
  %16 = load i8, i8* %strcmp.char_l, align 1
  %17 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 0
  %probe_read_kernel1 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %17)
  %18 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp = icmp ne i8 %16, %18
  br i1 %strcmp.cmp, label %strcmp.false, label %strcmp.loop_null_cmp

pred_false:                                       ; preds = %strcmp.false
  ret i64 1

pred_true:                                        ; preds = %strcmp.false
  %19 = bitcast i64* %"@_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %19)
  store i64 0, i64* %"@_key", align 8
  %20 = bitcast i64* %"@_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %20)
  store i64 1, i64* %"@_val", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo, i64* %"@_key", i64* %"@_val", i64 0)
  %21 = bitcast i64* %"@_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %21)
  %22 = bitcast i64* %"@_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %22)
  ret i64 1

strcmp.false:                                     ; preds = %strcmp.done, %strcmp.loop86, %strcmp.loop80, %strcmp.loop74, %strcmp.loop68, %strcmp.loop62, %strcmp.loop56, %strcmp.loop50, %strcmp.loop44, %strcmp.loop38, %strcmp.loop32, %strcmp.loop26, %strcmp.loop20, %strcmp.loop14, %strcmp.loop8, %strcmp.loop2, %strcmp.loop, %entry
  %23 = load i1, i1* %strcmp.result, align 1
  %24 = bitcast i1* %strcmp.result to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %24)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %strcmp.char_l)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %strcmp.char_r)
  %25 = zext i1 %23 to i64
  %26 = bitcast [64 x i8]* %str to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %26)
  %27 = bitcast [16 x i8]* %comm to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %27)
  %predcond = icmp eq i64 %25, 0
  br i1 %predcond, label %pred_false, label %pred_true

strcmp.done:                                      ; preds = %strcmp.loop92, %strcmp.loop_null_cmp93, %strcmp.loop_null_cmp87, %strcmp.loop_null_cmp81, %strcmp.loop_null_cmp75, %strcmp.loop_null_cmp69, %strcmp.loop_null_cmp63, %strcmp.loop_null_cmp57, %strcmp.loop_null_cmp51, %strcmp.loop_null_cmp45, %strcmp.loop_null_cmp39, %strcmp.loop_null_cmp33, %strcmp.loop_null_cmp27, %strcmp.loop_null_cmp21, %strcmp.loop_null_cmp15, %strcmp.loop_null_cmp9, %strcmp.loop_null_cmp3, %strcmp.loop_null_cmp
  store i1 true, i1* %strcmp.result, align 1
  br label %strcmp.false

strcmp.loop:                                      ; preds = %strcmp.loop_null_cmp
  %28 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 1
  %probe_read_kernel4 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %28)
  %29 = load i8, i8* %strcmp.char_l, align 1
  %30 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 1
  %probe_read_kernel5 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %30)
  %31 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp6 = icmp ne i8 %29, %31
  br i1 %strcmp.cmp6, label %strcmp.false, label %strcmp.loop_null_cmp3

strcmp.loop_null_cmp:                             ; preds = %entry
  %strcmp.cmp_null = icmp eq i8 %16, 0
  br i1 %strcmp.cmp_null, label %strcmp.done, label %strcmp.loop

strcmp.loop2:                                     ; preds = %strcmp.loop_null_cmp3
  %32 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 2
  %probe_read_kernel10 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %32)
  %33 = load i8, i8* %strcmp.char_l, align 1
  %34 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 2
  %probe_read_kernel11 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %34)
  %35 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp12 = icmp ne i8 %33, %35
  br i1 %strcmp.cmp12, label %strcmp.false, label %strcmp.loop_null_cmp9

strcmp.loop_null_cmp3:                            ; preds = %strcmp.loop
  %strcmp.cmp_null7 = icmp eq i8 %29, 0
  br i1 %strcmp.cmp_null7, label %strcmp.done, label %strcmp.loop2

strcmp.loop8:                                     ; preds = %strcmp.loop_null_cmp9
  %36 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 3
  %probe_read_kernel16 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %36)
  %37 = load i8, i8* %strcmp.char_l, align 1
  %38 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 3
  %probe_read_kernel17 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %38)
  %39 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp18 = icmp ne i8 %37, %39
  br i1 %strcmp.cmp18, label %strcmp.false, label %strcmp.loop_null_cmp15

strcmp.loop_null_cmp9:                            ; preds = %strcmp.loop2
  %strcmp.cmp_null13 = icmp eq i8 %33, 0
  br i1 %strcmp.cmp_null13, label %strcmp.done, label %strcmp.loop8

strcmp.loop14:                                    ; preds = %strcmp.loop_null_cmp15
  %40 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 4
  %probe_read_kernel22 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %40)
  %41 = load i8, i8* %strcmp.char_l, align 1
  %42 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 4
  %probe_read_kernel23 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %42)
  %43 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp24 = icmp ne i8 %41, %43
  br i1 %strcmp.cmp24, label %strcmp.false, label %strcmp.loop_null_cmp21

strcmp.loop_null_cmp15:                           ; preds = %strcmp.loop8
  %strcmp.cmp_null19 = icmp eq i8 %37, 0
  br i1 %strcmp.cmp_null19, label %strcmp.done, label %strcmp.loop14

strcmp.loop20:                                    ; preds = %strcmp.loop_null_cmp21
  %44 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 5
  %probe_read_kernel28 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %44)
  %45 = load i8, i8* %strcmp.char_l, align 1
  %46 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 5
  %probe_read_kernel29 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %46)
  %47 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp30 = icmp ne i8 %45, %47
  br i1 %strcmp.cmp30, label %strcmp.false, label %strcmp.loop_null_cmp27

strcmp.loop_null_cmp21:                           ; preds = %strcmp.loop14
  %strcmp.cmp_null25 = icmp eq i8 %41, 0
  br i1 %strcmp.cmp_null25, label %strcmp.done, label %strcmp.loop20

strcmp.loop26:                                    ; preds = %strcmp.loop_null_cmp27
  %48 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 6
  %probe_read_kernel34 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %48)
  %49 = load i8, i8* %strcmp.char_l, align 1
  %50 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 6
  %probe_read_kernel35 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %50)
  %51 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp36 = icmp ne i8 %49, %51
  br i1 %strcmp.cmp36, label %strcmp.false, label %strcmp.loop_null_cmp33

strcmp.loop_null_cmp27:                           ; preds = %strcmp.loop20
  %strcmp.cmp_null31 = icmp eq i8 %45, 0
  br i1 %strcmp.cmp_null31, label %strcmp.done, label %strcmp.loop26

strcmp.loop32:                                    ; preds = %strcmp.loop_null_cmp33
  %52 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 7
  %probe_read_kernel40 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %52)
  %53 = load i8, i8* %strcmp.char_l, align 1
  %54 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 7
  %probe_read_kernel41 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %54)
  %55 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp42 = icmp ne i8 %53, %55
  br i1 %strcmp.cmp42, label %strcmp.false, label %strcmp.loop_null_cmp39

strcmp.loop_null_cmp33:                           ; preds = %strcmp.loop26
  %strcmp.cmp_null37 = icmp eq i8 %49, 0
  br i1 %strcmp.cmp_null37, label %strcmp.done, label %strcmp.loop32

strcmp.loop38:                                    ; preds = %strcmp.loop_null_cmp39
  %56 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 8
  %probe_read_kernel46 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %56)
  %57 = load i8, i8* %strcmp.char_l, align 1
  %58 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 8
  %probe_read_kernel47 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %58)
  %59 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp48 = icmp ne i8 %57, %59
  br i1 %strcmp.cmp48, label %strcmp.false, label %strcmp.loop_null_cmp45

strcmp.loop_null_cmp39:                           ; preds = %strcmp.loop32
  %strcmp.cmp_null43 = icmp eq i8 %53, 0
  br i1 %strcmp.cmp_null43, label %strcmp.done, label %strcmp.loop38

strcmp.loop44:                                    ; preds = %strcmp.loop_null_cmp45
  %60 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 9
  %probe_read_kernel52 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %60)
  %61 = load i8, i8* %strcmp.char_l, align 1
  %62 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 9
  %probe_read_kernel53 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %62)
  %63 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp54 = icmp ne i8 %61, %63
  br i1 %strcmp.cmp54, label %strcmp.false, label %strcmp.loop_null_cmp51

strcmp.loop_null_cmp45:                           ; preds = %strcmp.loop38
  %strcmp.cmp_null49 = icmp eq i8 %57, 0
  br i1 %strcmp.cmp_null49, label %strcmp.done, label %strcmp.loop44

strcmp.loop50:                                    ; preds = %strcmp.loop_null_cmp51
  %64 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 10
  %probe_read_kernel58 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %64)
  %65 = load i8, i8* %strcmp.char_l, align 1
  %66 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 10
  %probe_read_kernel59 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %66)
  %67 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp60 = icmp ne i8 %65, %67
  br i1 %strcmp.cmp60, label %strcmp.false, label %strcmp.loop_null_cmp57

strcmp.loop_null_cmp51:                           ; preds = %strcmp.loop44
  %strcmp.cmp_null55 = icmp eq i8 %61, 0
  br i1 %strcmp.cmp_null55, label %strcmp.done, label %strcmp.loop50

strcmp.loop56:                                    ; preds = %strcmp.loop_null_cmp57
  %68 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 11
  %probe_read_kernel64 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %68)
  %69 = load i8, i8* %strcmp.char_l, align 1
  %70 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 11
  %probe_read_kernel65 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %70)
  %71 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp66 = icmp ne i8 %69, %71
  br i1 %strcmp.cmp66, label %strcmp.false, label %strcmp.loop_null_cmp63

strcmp.loop_null_cmp57:                           ; preds = %strcmp.loop50
  %strcmp.cmp_null61 = icmp eq i8 %65, 0
  br i1 %strcmp.cmp_null61, label %strcmp.done, label %strcmp.loop56

strcmp.loop62:                                    ; preds = %strcmp.loop_null_cmp63
  %72 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 12
  %probe_read_kernel70 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %72)
  %73 = load i8, i8* %strcmp.char_l, align 1
  %74 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 12
  %probe_read_kernel71 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %74)
  %75 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp72 = icmp ne i8 %73, %75
  br i1 %strcmp.cmp72, label %strcmp.false, label %strcmp.loop_null_cmp69

strcmp.loop_null_cmp63:                           ; preds = %strcmp.loop56
  %strcmp.cmp_null67 = icmp eq i8 %69, 0
  br i1 %strcmp.cmp_null67, label %strcmp.done, label %strcmp.loop62

strcmp.loop68:                                    ; preds = %strcmp.loop_null_cmp69
  %76 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 13
  %probe_read_kernel76 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %76)
  %77 = load i8, i8* %strcmp.char_l, align 1
  %78 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 13
  %probe_read_kernel77 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %78)
  %79 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp78 = icmp ne i8 %77, %79
  br i1 %strcmp.cmp78, label %strcmp.false, label %strcmp.loop_null_cmp75

strcmp.loop_null_cmp69:                           ; preds = %strcmp.loop62
  %strcmp.cmp_null73 = icmp eq i8 %73, 0
  br i1 %strcmp.cmp_null73, label %strcmp.done, label %strcmp.loop68

strcmp.loop74:                                    ; preds = %strcmp.loop_null_cmp75
  %80 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 14
  %probe_read_kernel82 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %80)
  %81 = load i8, i8* %strcmp.char_l, align 1
  %82 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 14
  %probe_read_kernel83 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %82)
  %83 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp84 = icmp ne i8 %81, %83
  br i1 %strcmp.cmp84, label %strcmp.false, label %strcmp.loop_null_cmp81

strcmp.loop_null_cmp75:                           ; preds = %strcmp.loop68
  %strcmp.cmp_null79 = icmp eq i8 %77, 0
  br i1 %strcmp.cmp_null79, label %strcmp.done, label %strcmp.loop74

strcmp.loop80:                                    ; preds = %strcmp.loop_null_cmp81
  %84 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 15
  %probe_read_kernel88 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %84)
  %85 = load i8, i8* %strcmp.char_l, align 1
  %86 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 15
  %probe_read_kernel89 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %86)
  %87 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp90 = icmp ne i8 %85, %87
  br i1 %strcmp.cmp90, label %strcmp.false, label %strcmp.loop_null_cmp87

strcmp.loop_null_cmp81:                           ; preds = %strcmp.loop74
  %strcmp.cmp_null85 = icmp eq i8 %81, 0
  br i1 %strcmp.cmp_null85, label %strcmp.done, label %strcmp.loop80

strcmp.loop86:                                    ; preds = %strcmp.loop_null_cmp87
  %88 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 16
  %probe_read_kernel94 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %88)
  %89 = load i8, i8* %strcmp.char_l, align 1
  %90 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 16
  %probe_read_kernel95 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %90)
  %91 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp96 = icmp ne i8 %89, %91
  br i1 %strcmp.cmp96, label %strcmp.false, label %strcmp.loop_null_cmp93

strcmp.loop_null_cmp87:                           ; preds = %strcmp.loop80
  %strcmp.cmp_null91 = icmp eq i8 %85, 0
  br i1 %strcmp.cmp_null91, label %strcmp.done, label %strcmp.loop86

strcmp.loop92:                                    ; preds = %strcmp.loop_null_cmp93
  br label %strcmp.done

strcmp.loop_null_cmp93:                           ; preds = %strcmp.loop86
  %strcmp.cmp_null97 = icmp eq i8 %89, 0
  br i1 %strcmp.cmp_null97, label %strcmp.done, label %strcmp.loop92
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
