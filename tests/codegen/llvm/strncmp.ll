; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

%helper_error_t = type <{ i64, i64, i32, i8 }>

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

define i64 @"tracepoint:file:filename"(i8*) section "s_tracepoint:file:filename_1" {
entry:
  %"@_key" = alloca i64
  %"@_val" = alloca i64
  %strcmp.char_r = alloca i8
  %strcmp.char_l = alloca i8
  %strcmp.result = alloca i1
  %helper_error_t = alloca %helper_error_t
  %lookup_str_key = alloca i32
  %strlen = alloca i64
  %comm = alloca [16 x i8]
  %1 = bitcast [16 x i8]* %comm to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  %2 = bitcast [16 x i8]* %comm to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %2, i8 0, i64 16, i1 false)
  %get_comm = call i64 inttoptr (i64 16 to i64 ([16 x i8]*, i64)*)([16 x i8]* %comm, i64 16)
  %3 = bitcast i64* %strlen to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %3)
  store i64 64, i64* %strlen
  %4 = bitcast i32* %lookup_str_key to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %4)
  store i32 0, i32* %lookup_str_key
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 3)
  %lookup_str_map = call [64 x i8]* inttoptr (i64 1 to [64 x i8]* (i64, i32*)*)(i64 %pseudo, i32* %lookup_str_key)
  %5 = bitcast i32* %lookup_str_key to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %5)
  %6 = sext [64 x i8]* %lookup_str_map to i32
  %7 = icmp ne i32 %6, 0
  br i1 %7, label %helper_merge, label %helper_failure

pred_false:                                       ; preds = %strcmp.false
  ret i64 0

pred_true:                                        ; preds = %strcmp.false
  %8 = bitcast i64* %"@_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %8)
  store i64 1, i64* %"@_val"
  %9 = bitcast i64* %"@_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %9)
  store i64 0, i64* %"@_key"
  %pseudo93 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo93, i64* %"@_key", i64* %"@_val", i64 0)
  %10 = bitcast i64* %"@_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %10)
  %11 = bitcast i64* %"@_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %11)
  ret i64 0

helper_failure:                                   ; preds = %entry
  %12 = bitcast %helper_error_t* %helper_error_t to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %12)
  %13 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 0
  store i64 30006, i64* %13
  %14 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 1
  store i64 0, i64* %14
  %15 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 2
  store i32 %6, i32* %15
  %16 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 3
  store i8 1, i8* %16
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %helper_error_t*, i64)*)(i8* %0, i64 %pseudo1, i64 4294967295, %helper_error_t* %helper_error_t, i64 21)
  %17 = bitcast %helper_error_t* %helper_error_t to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %17)
  ret i64 0

helper_merge:                                     ; preds = %entry
  %18 = bitcast [64 x i8]* %lookup_str_map to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %18, i8 0, i64 64, i1 false)
  %19 = ptrtoint i8* %0 to i64
  %20 = add i64 %19, 8
  %21 = inttoptr i64 %20 to i64*
  %22 = load volatile i64, i64* %21
  %23 = load i64, i64* %strlen
  %probe_read_str = call i64 inttoptr (i64 45 to i64 ([64 x i8]*, i32, i64)*)([64 x i8]* %lookup_str_map, i64 %23, i64 %22)
  %24 = bitcast i64* %strlen to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %24)
  %25 = bitcast i1* %strcmp.result to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %25)
  store i1 false, i1* %strcmp.result
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %strcmp.char_l)
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %strcmp.char_r)
  %26 = getelementptr [64 x i8], [64 x i8]* %lookup_str_map, i32 0, i32 0
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %26)
  %27 = load i8, i8* %strcmp.char_l
  %28 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 0
  %probe_read2 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %28)
  %29 = load i8, i8* %strcmp.char_r
  %strcmp.cmp = icmp ne i8 %27, %29
  br i1 %strcmp.cmp, label %strcmp.false, label %strcmp.loop_null_cmp

strcmp.false:                                     ; preds = %strcmp.done, %strcmp.loop81, %strcmp.loop75, %strcmp.loop69, %strcmp.loop63, %strcmp.loop57, %strcmp.loop51, %strcmp.loop45, %strcmp.loop39, %strcmp.loop33, %strcmp.loop27, %strcmp.loop21, %strcmp.loop15, %strcmp.loop9, %strcmp.loop3, %strcmp.loop, %helper_merge
  %30 = load i1, i1* %strcmp.result
  %31 = bitcast i1* %strcmp.result to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %31)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %strcmp.char_l)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %strcmp.char_r)
  %32 = zext i1 %30 to i64
  %33 = bitcast [16 x i8]* %comm to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %33)
  %predcond = icmp eq i64 %32, 0
  br i1 %predcond, label %pred_false, label %pred_true

strcmp.done:                                      ; preds = %strcmp.loop87, %strcmp.loop_null_cmp88, %strcmp.loop_null_cmp82, %strcmp.loop_null_cmp76, %strcmp.loop_null_cmp70, %strcmp.loop_null_cmp64, %strcmp.loop_null_cmp58, %strcmp.loop_null_cmp52, %strcmp.loop_null_cmp46, %strcmp.loop_null_cmp40, %strcmp.loop_null_cmp34, %strcmp.loop_null_cmp28, %strcmp.loop_null_cmp22, %strcmp.loop_null_cmp16, %strcmp.loop_null_cmp10, %strcmp.loop_null_cmp4, %strcmp.loop_null_cmp
  store i1 true, i1* %strcmp.result
  br label %strcmp.false

strcmp.loop:                                      ; preds = %strcmp.loop_null_cmp
  %34 = getelementptr [64 x i8], [64 x i8]* %lookup_str_map, i32 0, i32 1
  %probe_read5 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %34)
  %35 = load i8, i8* %strcmp.char_l
  %36 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 1
  %probe_read6 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %36)
  %37 = load i8, i8* %strcmp.char_r
  %strcmp.cmp7 = icmp ne i8 %35, %37
  br i1 %strcmp.cmp7, label %strcmp.false, label %strcmp.loop_null_cmp4

strcmp.loop_null_cmp:                             ; preds = %helper_merge
  %strcmp.cmp_null = icmp eq i8 %27, 0
  br i1 %strcmp.cmp_null, label %strcmp.done, label %strcmp.loop

strcmp.loop3:                                     ; preds = %strcmp.loop_null_cmp4
  %38 = getelementptr [64 x i8], [64 x i8]* %lookup_str_map, i32 0, i32 2
  %probe_read11 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %38)
  %39 = load i8, i8* %strcmp.char_l
  %40 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 2
  %probe_read12 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %40)
  %41 = load i8, i8* %strcmp.char_r
  %strcmp.cmp13 = icmp ne i8 %39, %41
  br i1 %strcmp.cmp13, label %strcmp.false, label %strcmp.loop_null_cmp10

strcmp.loop_null_cmp4:                            ; preds = %strcmp.loop
  %strcmp.cmp_null8 = icmp eq i8 %35, 0
  br i1 %strcmp.cmp_null8, label %strcmp.done, label %strcmp.loop3

strcmp.loop9:                                     ; preds = %strcmp.loop_null_cmp10
  %42 = getelementptr [64 x i8], [64 x i8]* %lookup_str_map, i32 0, i32 3
  %probe_read17 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %42)
  %43 = load i8, i8* %strcmp.char_l
  %44 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 3
  %probe_read18 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %44)
  %45 = load i8, i8* %strcmp.char_r
  %strcmp.cmp19 = icmp ne i8 %43, %45
  br i1 %strcmp.cmp19, label %strcmp.false, label %strcmp.loop_null_cmp16

strcmp.loop_null_cmp10:                           ; preds = %strcmp.loop3
  %strcmp.cmp_null14 = icmp eq i8 %39, 0
  br i1 %strcmp.cmp_null14, label %strcmp.done, label %strcmp.loop9

strcmp.loop15:                                    ; preds = %strcmp.loop_null_cmp16
  %46 = getelementptr [64 x i8], [64 x i8]* %lookup_str_map, i32 0, i32 4
  %probe_read23 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %46)
  %47 = load i8, i8* %strcmp.char_l
  %48 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 4
  %probe_read24 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %48)
  %49 = load i8, i8* %strcmp.char_r
  %strcmp.cmp25 = icmp ne i8 %47, %49
  br i1 %strcmp.cmp25, label %strcmp.false, label %strcmp.loop_null_cmp22

strcmp.loop_null_cmp16:                           ; preds = %strcmp.loop9
  %strcmp.cmp_null20 = icmp eq i8 %43, 0
  br i1 %strcmp.cmp_null20, label %strcmp.done, label %strcmp.loop15

strcmp.loop21:                                    ; preds = %strcmp.loop_null_cmp22
  %50 = getelementptr [64 x i8], [64 x i8]* %lookup_str_map, i32 0, i32 5
  %probe_read29 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %50)
  %51 = load i8, i8* %strcmp.char_l
  %52 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 5
  %probe_read30 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %52)
  %53 = load i8, i8* %strcmp.char_r
  %strcmp.cmp31 = icmp ne i8 %51, %53
  br i1 %strcmp.cmp31, label %strcmp.false, label %strcmp.loop_null_cmp28

strcmp.loop_null_cmp22:                           ; preds = %strcmp.loop15
  %strcmp.cmp_null26 = icmp eq i8 %47, 0
  br i1 %strcmp.cmp_null26, label %strcmp.done, label %strcmp.loop21

strcmp.loop27:                                    ; preds = %strcmp.loop_null_cmp28
  %54 = getelementptr [64 x i8], [64 x i8]* %lookup_str_map, i32 0, i32 6
  %probe_read35 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %54)
  %55 = load i8, i8* %strcmp.char_l
  %56 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 6
  %probe_read36 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %56)
  %57 = load i8, i8* %strcmp.char_r
  %strcmp.cmp37 = icmp ne i8 %55, %57
  br i1 %strcmp.cmp37, label %strcmp.false, label %strcmp.loop_null_cmp34

strcmp.loop_null_cmp28:                           ; preds = %strcmp.loop21
  %strcmp.cmp_null32 = icmp eq i8 %51, 0
  br i1 %strcmp.cmp_null32, label %strcmp.done, label %strcmp.loop27

strcmp.loop33:                                    ; preds = %strcmp.loop_null_cmp34
  %58 = getelementptr [64 x i8], [64 x i8]* %lookup_str_map, i32 0, i32 7
  %probe_read41 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %58)
  %59 = load i8, i8* %strcmp.char_l
  %60 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 7
  %probe_read42 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %60)
  %61 = load i8, i8* %strcmp.char_r
  %strcmp.cmp43 = icmp ne i8 %59, %61
  br i1 %strcmp.cmp43, label %strcmp.false, label %strcmp.loop_null_cmp40

strcmp.loop_null_cmp34:                           ; preds = %strcmp.loop27
  %strcmp.cmp_null38 = icmp eq i8 %55, 0
  br i1 %strcmp.cmp_null38, label %strcmp.done, label %strcmp.loop33

strcmp.loop39:                                    ; preds = %strcmp.loop_null_cmp40
  %62 = getelementptr [64 x i8], [64 x i8]* %lookup_str_map, i32 0, i32 8
  %probe_read47 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %62)
  %63 = load i8, i8* %strcmp.char_l
  %64 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 8
  %probe_read48 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %64)
  %65 = load i8, i8* %strcmp.char_r
  %strcmp.cmp49 = icmp ne i8 %63, %65
  br i1 %strcmp.cmp49, label %strcmp.false, label %strcmp.loop_null_cmp46

strcmp.loop_null_cmp40:                           ; preds = %strcmp.loop33
  %strcmp.cmp_null44 = icmp eq i8 %59, 0
  br i1 %strcmp.cmp_null44, label %strcmp.done, label %strcmp.loop39

strcmp.loop45:                                    ; preds = %strcmp.loop_null_cmp46
  %66 = getelementptr [64 x i8], [64 x i8]* %lookup_str_map, i32 0, i32 9
  %probe_read53 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %66)
  %67 = load i8, i8* %strcmp.char_l
  %68 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 9
  %probe_read54 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %68)
  %69 = load i8, i8* %strcmp.char_r
  %strcmp.cmp55 = icmp ne i8 %67, %69
  br i1 %strcmp.cmp55, label %strcmp.false, label %strcmp.loop_null_cmp52

strcmp.loop_null_cmp46:                           ; preds = %strcmp.loop39
  %strcmp.cmp_null50 = icmp eq i8 %63, 0
  br i1 %strcmp.cmp_null50, label %strcmp.done, label %strcmp.loop45

strcmp.loop51:                                    ; preds = %strcmp.loop_null_cmp52
  %70 = getelementptr [64 x i8], [64 x i8]* %lookup_str_map, i32 0, i32 10
  %probe_read59 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %70)
  %71 = load i8, i8* %strcmp.char_l
  %72 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 10
  %probe_read60 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %72)
  %73 = load i8, i8* %strcmp.char_r
  %strcmp.cmp61 = icmp ne i8 %71, %73
  br i1 %strcmp.cmp61, label %strcmp.false, label %strcmp.loop_null_cmp58

strcmp.loop_null_cmp52:                           ; preds = %strcmp.loop45
  %strcmp.cmp_null56 = icmp eq i8 %67, 0
  br i1 %strcmp.cmp_null56, label %strcmp.done, label %strcmp.loop51

strcmp.loop57:                                    ; preds = %strcmp.loop_null_cmp58
  %74 = getelementptr [64 x i8], [64 x i8]* %lookup_str_map, i32 0, i32 11
  %probe_read65 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %74)
  %75 = load i8, i8* %strcmp.char_l
  %76 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 11
  %probe_read66 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %76)
  %77 = load i8, i8* %strcmp.char_r
  %strcmp.cmp67 = icmp ne i8 %75, %77
  br i1 %strcmp.cmp67, label %strcmp.false, label %strcmp.loop_null_cmp64

strcmp.loop_null_cmp58:                           ; preds = %strcmp.loop51
  %strcmp.cmp_null62 = icmp eq i8 %71, 0
  br i1 %strcmp.cmp_null62, label %strcmp.done, label %strcmp.loop57

strcmp.loop63:                                    ; preds = %strcmp.loop_null_cmp64
  %78 = getelementptr [64 x i8], [64 x i8]* %lookup_str_map, i32 0, i32 12
  %probe_read71 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %78)
  %79 = load i8, i8* %strcmp.char_l
  %80 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 12
  %probe_read72 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %80)
  %81 = load i8, i8* %strcmp.char_r
  %strcmp.cmp73 = icmp ne i8 %79, %81
  br i1 %strcmp.cmp73, label %strcmp.false, label %strcmp.loop_null_cmp70

strcmp.loop_null_cmp64:                           ; preds = %strcmp.loop57
  %strcmp.cmp_null68 = icmp eq i8 %75, 0
  br i1 %strcmp.cmp_null68, label %strcmp.done, label %strcmp.loop63

strcmp.loop69:                                    ; preds = %strcmp.loop_null_cmp70
  %82 = getelementptr [64 x i8], [64 x i8]* %lookup_str_map, i32 0, i32 13
  %probe_read77 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %82)
  %83 = load i8, i8* %strcmp.char_l
  %84 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 13
  %probe_read78 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %84)
  %85 = load i8, i8* %strcmp.char_r
  %strcmp.cmp79 = icmp ne i8 %83, %85
  br i1 %strcmp.cmp79, label %strcmp.false, label %strcmp.loop_null_cmp76

strcmp.loop_null_cmp70:                           ; preds = %strcmp.loop63
  %strcmp.cmp_null74 = icmp eq i8 %79, 0
  br i1 %strcmp.cmp_null74, label %strcmp.done, label %strcmp.loop69

strcmp.loop75:                                    ; preds = %strcmp.loop_null_cmp76
  %86 = getelementptr [64 x i8], [64 x i8]* %lookup_str_map, i32 0, i32 14
  %probe_read83 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %86)
  %87 = load i8, i8* %strcmp.char_l
  %88 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 14
  %probe_read84 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %88)
  %89 = load i8, i8* %strcmp.char_r
  %strcmp.cmp85 = icmp ne i8 %87, %89
  br i1 %strcmp.cmp85, label %strcmp.false, label %strcmp.loop_null_cmp82

strcmp.loop_null_cmp76:                           ; preds = %strcmp.loop69
  %strcmp.cmp_null80 = icmp eq i8 %83, 0
  br i1 %strcmp.cmp_null80, label %strcmp.done, label %strcmp.loop75

strcmp.loop81:                                    ; preds = %strcmp.loop_null_cmp82
  %90 = getelementptr [64 x i8], [64 x i8]* %lookup_str_map, i32 0, i32 15
  %probe_read89 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_l, i32 1, i8* %90)
  %91 = load i8, i8* %strcmp.char_l
  %92 = getelementptr [16 x i8], [16 x i8]* %comm, i32 0, i32 15
  %probe_read90 = call i64 inttoptr (i64 4 to i64 (i8*, i32, i8*)*)(i8* %strcmp.char_r, i32 1, i8* %92)
  %93 = load i8, i8* %strcmp.char_r
  %strcmp.cmp91 = icmp ne i8 %91, %93
  br i1 %strcmp.cmp91, label %strcmp.false, label %strcmp.loop_null_cmp88

strcmp.loop_null_cmp82:                           ; preds = %strcmp.loop75
  %strcmp.cmp_null86 = icmp eq i8 %87, 0
  br i1 %strcmp.cmp_null86, label %strcmp.done, label %strcmp.loop81

strcmp.loop87:                                    ; preds = %strcmp.loop_null_cmp88
  br label %strcmp.done

strcmp.loop_null_cmp88:                           ; preds = %strcmp.loop81
  %strcmp.cmp_null92 = icmp eq i8 %91, 0
  br i1 %strcmp.cmp_null92, label %strcmp.done, label %strcmp.loop87
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i1) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
