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
  %strcmp.result = alloca i8
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
  %probe_read_str = call i64 inttoptr (i64 45 to i64 ([64 x i8]*, i32, i64)*)([64 x i8]* %str, i32 %12, i64 %10)
  %13 = bitcast i64* %strlen to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %13)
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %strcmp.result)
  store i1 false, i8* %strcmp.result
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %strcmp.char_l)
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %strcmp.char_r)
  %14 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 0
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %14)
  %15 = load i8, i8* %strcmp.char_l
  %16 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 0
  %probe_read1 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %16)
  %17 = load i8, i8* %strcmp.char_r
  %strcmp.cmp = icmp ne i8 %15, %17
  br i1 %strcmp.cmp, label %strcmp.false, label %strcmp.loop_null_cmp

pred_false:                                       ; preds = %strcmp.false
  ret i64 0

pred_true:                                        ; preds = %strcmp.false
  %18 = bitcast i64* %"@_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %18)
  store i64 0, i64* %"@_key"
  %19 = bitcast i64* %"@_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %19)
  store i64 1, i64* %"@_val"
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo, i64* %"@_key", i64* %"@_val", i64 0)
  %20 = bitcast i64* %"@_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %20)
  %21 = bitcast i64* %"@_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %21)
  ret i64 0

strcmp.false:                                     ; preds = %strcmp.done, %strcmp.loop86, %strcmp.loop80, %strcmp.loop74, %strcmp.loop68, %strcmp.loop62, %strcmp.loop56, %strcmp.loop50, %strcmp.loop44, %strcmp.loop38, %strcmp.loop32, %strcmp.loop26, %strcmp.loop20, %strcmp.loop14, %strcmp.loop8, %strcmp.loop2, %strcmp.loop, %entry
  %22 = load i8, i8* %strcmp.result
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %strcmp.result)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %strcmp.char_l)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %strcmp.char_r)
  %23 = zext i8 %22 to i64
  %24 = bitcast [64 x i8]* %str to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %24)
  %25 = bitcast [16 x i8]* %comm to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %25)
  %predcond = icmp eq i64 %23, 0
  br i1 %predcond, label %pred_false, label %pred_true

strcmp.done:                                      ; preds = %strcmp.loop92, %strcmp.loop_null_cmp93, %strcmp.loop_null_cmp87, %strcmp.loop_null_cmp81, %strcmp.loop_null_cmp75, %strcmp.loop_null_cmp69, %strcmp.loop_null_cmp63, %strcmp.loop_null_cmp57, %strcmp.loop_null_cmp51, %strcmp.loop_null_cmp45, %strcmp.loop_null_cmp39, %strcmp.loop_null_cmp33, %strcmp.loop_null_cmp27, %strcmp.loop_null_cmp21, %strcmp.loop_null_cmp15, %strcmp.loop_null_cmp9, %strcmp.loop_null_cmp3, %strcmp.loop_null_cmp
  store i1 true, i8* %strcmp.result
  br label %strcmp.false

strcmp.loop:                                      ; preds = %strcmp.loop_null_cmp
  %26 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 1
  %probe_read4 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %26)
  %27 = load i8, i8* %strcmp.char_l
  %28 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 1
  %probe_read5 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %28)
  %29 = load i8, i8* %strcmp.char_r
  %strcmp.cmp6 = icmp ne i8 %27, %29
  br i1 %strcmp.cmp6, label %strcmp.false, label %strcmp.loop_null_cmp3

strcmp.loop_null_cmp:                             ; preds = %entry
  %strcmp.cmp_null = icmp eq i8 %15, 0
  br i1 %strcmp.cmp_null, label %strcmp.done, label %strcmp.loop

strcmp.loop2:                                     ; preds = %strcmp.loop_null_cmp3
  %30 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 2
  %probe_read10 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %30)
  %31 = load i8, i8* %strcmp.char_l
  %32 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 2
  %probe_read11 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %32)
  %33 = load i8, i8* %strcmp.char_r
  %strcmp.cmp12 = icmp ne i8 %31, %33
  br i1 %strcmp.cmp12, label %strcmp.false, label %strcmp.loop_null_cmp9

strcmp.loop_null_cmp3:                            ; preds = %strcmp.loop
  %strcmp.cmp_null7 = icmp eq i8 %27, 0
  br i1 %strcmp.cmp_null7, label %strcmp.done, label %strcmp.loop2

strcmp.loop8:                                     ; preds = %strcmp.loop_null_cmp9
  %34 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 3
  %probe_read16 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %34)
  %35 = load i8, i8* %strcmp.char_l
  %36 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 3
  %probe_read17 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %36)
  %37 = load i8, i8* %strcmp.char_r
  %strcmp.cmp18 = icmp ne i8 %35, %37
  br i1 %strcmp.cmp18, label %strcmp.false, label %strcmp.loop_null_cmp15

strcmp.loop_null_cmp9:                            ; preds = %strcmp.loop2
  %strcmp.cmp_null13 = icmp eq i8 %31, 0
  br i1 %strcmp.cmp_null13, label %strcmp.done, label %strcmp.loop8

strcmp.loop14:                                    ; preds = %strcmp.loop_null_cmp15
  %38 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 4
  %probe_read22 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %38)
  %39 = load i8, i8* %strcmp.char_l
  %40 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 4
  %probe_read23 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %40)
  %41 = load i8, i8* %strcmp.char_r
  %strcmp.cmp24 = icmp ne i8 %39, %41
  br i1 %strcmp.cmp24, label %strcmp.false, label %strcmp.loop_null_cmp21

strcmp.loop_null_cmp15:                           ; preds = %strcmp.loop8
  %strcmp.cmp_null19 = icmp eq i8 %35, 0
  br i1 %strcmp.cmp_null19, label %strcmp.done, label %strcmp.loop14

strcmp.loop20:                                    ; preds = %strcmp.loop_null_cmp21
  %42 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 5
  %probe_read28 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %42)
  %43 = load i8, i8* %strcmp.char_l
  %44 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 5
  %probe_read29 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %44)
  %45 = load i8, i8* %strcmp.char_r
  %strcmp.cmp30 = icmp ne i8 %43, %45
  br i1 %strcmp.cmp30, label %strcmp.false, label %strcmp.loop_null_cmp27

strcmp.loop_null_cmp21:                           ; preds = %strcmp.loop14
  %strcmp.cmp_null25 = icmp eq i8 %39, 0
  br i1 %strcmp.cmp_null25, label %strcmp.done, label %strcmp.loop20

strcmp.loop26:                                    ; preds = %strcmp.loop_null_cmp27
  %46 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 6
  %probe_read34 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %46)
  %47 = load i8, i8* %strcmp.char_l
  %48 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 6
  %probe_read35 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %48)
  %49 = load i8, i8* %strcmp.char_r
  %strcmp.cmp36 = icmp ne i8 %47, %49
  br i1 %strcmp.cmp36, label %strcmp.false, label %strcmp.loop_null_cmp33

strcmp.loop_null_cmp27:                           ; preds = %strcmp.loop20
  %strcmp.cmp_null31 = icmp eq i8 %43, 0
  br i1 %strcmp.cmp_null31, label %strcmp.done, label %strcmp.loop26

strcmp.loop32:                                    ; preds = %strcmp.loop_null_cmp33
  %50 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 7
  %probe_read40 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %50)
  %51 = load i8, i8* %strcmp.char_l
  %52 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 7
  %probe_read41 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %52)
  %53 = load i8, i8* %strcmp.char_r
  %strcmp.cmp42 = icmp ne i8 %51, %53
  br i1 %strcmp.cmp42, label %strcmp.false, label %strcmp.loop_null_cmp39

strcmp.loop_null_cmp33:                           ; preds = %strcmp.loop26
  %strcmp.cmp_null37 = icmp eq i8 %47, 0
  br i1 %strcmp.cmp_null37, label %strcmp.done, label %strcmp.loop32

strcmp.loop38:                                    ; preds = %strcmp.loop_null_cmp39
  %54 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 8
  %probe_read46 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %54)
  %55 = load i8, i8* %strcmp.char_l
  %56 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 8
  %probe_read47 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %56)
  %57 = load i8, i8* %strcmp.char_r
  %strcmp.cmp48 = icmp ne i8 %55, %57
  br i1 %strcmp.cmp48, label %strcmp.false, label %strcmp.loop_null_cmp45

strcmp.loop_null_cmp39:                           ; preds = %strcmp.loop32
  %strcmp.cmp_null43 = icmp eq i8 %51, 0
  br i1 %strcmp.cmp_null43, label %strcmp.done, label %strcmp.loop38

strcmp.loop44:                                    ; preds = %strcmp.loop_null_cmp45
  %58 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 9
  %probe_read52 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %58)
  %59 = load i8, i8* %strcmp.char_l
  %60 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 9
  %probe_read53 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %60)
  %61 = load i8, i8* %strcmp.char_r
  %strcmp.cmp54 = icmp ne i8 %59, %61
  br i1 %strcmp.cmp54, label %strcmp.false, label %strcmp.loop_null_cmp51

strcmp.loop_null_cmp45:                           ; preds = %strcmp.loop38
  %strcmp.cmp_null49 = icmp eq i8 %55, 0
  br i1 %strcmp.cmp_null49, label %strcmp.done, label %strcmp.loop44

strcmp.loop50:                                    ; preds = %strcmp.loop_null_cmp51
  %62 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 10
  %probe_read58 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %62)
  %63 = load i8, i8* %strcmp.char_l
  %64 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 10
  %probe_read59 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %64)
  %65 = load i8, i8* %strcmp.char_r
  %strcmp.cmp60 = icmp ne i8 %63, %65
  br i1 %strcmp.cmp60, label %strcmp.false, label %strcmp.loop_null_cmp57

strcmp.loop_null_cmp51:                           ; preds = %strcmp.loop44
  %strcmp.cmp_null55 = icmp eq i8 %59, 0
  br i1 %strcmp.cmp_null55, label %strcmp.done, label %strcmp.loop50

strcmp.loop56:                                    ; preds = %strcmp.loop_null_cmp57
  %66 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 11
  %probe_read64 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %66)
  %67 = load i8, i8* %strcmp.char_l
  %68 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 11
  %probe_read65 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %68)
  %69 = load i8, i8* %strcmp.char_r
  %strcmp.cmp66 = icmp ne i8 %67, %69
  br i1 %strcmp.cmp66, label %strcmp.false, label %strcmp.loop_null_cmp63

strcmp.loop_null_cmp57:                           ; preds = %strcmp.loop50
  %strcmp.cmp_null61 = icmp eq i8 %63, 0
  br i1 %strcmp.cmp_null61, label %strcmp.done, label %strcmp.loop56

strcmp.loop62:                                    ; preds = %strcmp.loop_null_cmp63
  %70 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 12
  %probe_read70 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %70)
  %71 = load i8, i8* %strcmp.char_l
  %72 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 12
  %probe_read71 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %72)
  %73 = load i8, i8* %strcmp.char_r
  %strcmp.cmp72 = icmp ne i8 %71, %73
  br i1 %strcmp.cmp72, label %strcmp.false, label %strcmp.loop_null_cmp69

strcmp.loop_null_cmp63:                           ; preds = %strcmp.loop56
  %strcmp.cmp_null67 = icmp eq i8 %67, 0
  br i1 %strcmp.cmp_null67, label %strcmp.done, label %strcmp.loop62

strcmp.loop68:                                    ; preds = %strcmp.loop_null_cmp69
  %74 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 13
  %probe_read76 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %74)
  %75 = load i8, i8* %strcmp.char_l
  %76 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 13
  %probe_read77 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %76)
  %77 = load i8, i8* %strcmp.char_r
  %strcmp.cmp78 = icmp ne i8 %75, %77
  br i1 %strcmp.cmp78, label %strcmp.false, label %strcmp.loop_null_cmp75

strcmp.loop_null_cmp69:                           ; preds = %strcmp.loop62
  %strcmp.cmp_null73 = icmp eq i8 %71, 0
  br i1 %strcmp.cmp_null73, label %strcmp.done, label %strcmp.loop68

strcmp.loop74:                                    ; preds = %strcmp.loop_null_cmp75
  %78 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 14
  %probe_read82 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %78)
  %79 = load i8, i8* %strcmp.char_l
  %80 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 14
  %probe_read83 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %80)
  %81 = load i8, i8* %strcmp.char_r
  %strcmp.cmp84 = icmp ne i8 %79, %81
  br i1 %strcmp.cmp84, label %strcmp.false, label %strcmp.loop_null_cmp81

strcmp.loop_null_cmp75:                           ; preds = %strcmp.loop68
  %strcmp.cmp_null79 = icmp eq i8 %75, 0
  br i1 %strcmp.cmp_null79, label %strcmp.done, label %strcmp.loop74

strcmp.loop80:                                    ; preds = %strcmp.loop_null_cmp81
  %82 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 15
  %probe_read88 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %82)
  %83 = load i8, i8* %strcmp.char_l
  %84 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 15
  %probe_read89 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %84)
  %85 = load i8, i8* %strcmp.char_r
  %strcmp.cmp90 = icmp ne i8 %83, %85
  br i1 %strcmp.cmp90, label %strcmp.false, label %strcmp.loop_null_cmp87

strcmp.loop_null_cmp81:                           ; preds = %strcmp.loop74
  %strcmp.cmp_null85 = icmp eq i8 %79, 0
  br i1 %strcmp.cmp_null85, label %strcmp.done, label %strcmp.loop80

strcmp.loop86:                                    ; preds = %strcmp.loop_null_cmp87
  %86 = getelementptr [64 x i8], [64 x i8]* %str, i32 0, i32 16
  %probe_read94 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %86)
  %87 = load i8, i8* %strcmp.char_l
  %88 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 16
  %probe_read95 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %88)
  %89 = load i8, i8* %strcmp.char_r
  %strcmp.cmp96 = icmp ne i8 %87, %89
  br i1 %strcmp.cmp96, label %strcmp.false, label %strcmp.loop_null_cmp93

strcmp.loop_null_cmp87:                           ; preds = %strcmp.loop80
  %strcmp.cmp_null91 = icmp eq i8 %83, 0
  br i1 %strcmp.cmp_null91, label %strcmp.done, label %strcmp.loop86

strcmp.loop92:                                    ; preds = %strcmp.loop_null_cmp93
  br label %strcmp.done

strcmp.loop_null_cmp93:                           ; preds = %strcmp.loop86
  %strcmp.cmp_null97 = icmp eq i8 %87, 0
  br i1 %strcmp.cmp_null97, label %strcmp.done, label %strcmp.loop92
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i1) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
