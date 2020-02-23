; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64 immarg, i8* nocapture) #1

define i64 @"tracepoint:file:filename"(i8*) local_unnamed_addr section "s_tracepoint:file:filename_1" {
entry:
  %"@_val" = alloca i64, align 8
  %"@_key" = alloca i64, align 8
  %strcmp.char_r = alloca i8, align 1
  %strcmp.char_l = alloca i8, align 1
  %str = alloca [64 x i8], align 1
  %comm = alloca [16 x i8], align 1
  %1 = getelementptr inbounds [16 x i8], [16 x i8]* %comm, i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  call void @llvm.memset.p0i8.i64(i8* nonnull align 1 %1, i8 0, i64 16, i1 false)
  %get_comm = call i64 inttoptr (i64 16 to i64 ([16 x i8]*, i64)*)([16 x i8]* nonnull %comm, i64 16)
  %2 = getelementptr inbounds [64 x i8], [64 x i8]* %str, i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %2)
  call void @llvm.memset.p0i8.i64(i8* nonnull align 1 %2, i8 0, i64 64, i1 false)
  %3 = ptrtoint i8* %0 to i64
  %4 = add i64 %3, 8
  %5 = inttoptr i64 %4 to i64*
  %6 = load volatile i64, i64* %5, align 8
  %probe_read_str = call i64 inttoptr (i64 45 to i64 (i8*, i64, i8*)*)([64 x i8]* nonnull %str, i64 64, i64 %6)
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %strcmp.char_l)
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %strcmp.char_r)
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* nonnull %str)
  %7 = load i8, i8* %strcmp.char_l, align 1
  %probe_read1 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* nonnull %comm)
  %8 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp = icmp eq i8 %7, %8
  br i1 %strcmp.cmp, label %strcmp.loop_null_cmp, label %pred_false

pred_false:                                       ; preds = %entry, %strcmp.loop, %strcmp.loop2, %strcmp.loop8, %strcmp.loop14, %strcmp.loop20, %strcmp.loop26, %strcmp.loop32, %strcmp.loop38, %strcmp.loop44, %strcmp.loop50, %strcmp.loop56, %strcmp.loop62, %strcmp.loop68, %strcmp.loop74, %strcmp.loop80, %strcmp.loop86
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %strcmp.char_l)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %strcmp.char_r)
  ret i64 0

pred_true.critedge:                               ; preds = %strcmp.loop86, %strcmp.loop_null_cmp, %strcmp.loop_null_cmp3, %strcmp.loop_null_cmp9, %strcmp.loop_null_cmp15, %strcmp.loop_null_cmp21, %strcmp.loop_null_cmp27, %strcmp.loop_null_cmp33, %strcmp.loop_null_cmp39, %strcmp.loop_null_cmp45, %strcmp.loop_null_cmp51, %strcmp.loop_null_cmp57, %strcmp.loop_null_cmp63, %strcmp.loop_null_cmp69, %strcmp.loop_null_cmp75, %strcmp.loop_null_cmp81, %strcmp.loop_null_cmp87
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %strcmp.char_l)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %strcmp.char_r)
  %9 = bitcast i64* %"@_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %9)
  store i64 0, i64* %"@_key", align 8
  %10 = bitcast i64* %"@_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %10)
  store i64 1, i64* %"@_val", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo, i64* nonnull %"@_key", i64* nonnull %"@_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %9)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %10)
  ret i64 0

strcmp.loop:                                      ; preds = %strcmp.loop_null_cmp
  %11 = add [64 x i8]* %str, i64 1
  %probe_read4 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %11)
  %12 = load i8, i8* %strcmp.char_l, align 1
  %13 = add [16 x i8]* %comm, i64 1
  %probe_read5 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %13)
  %14 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp6 = icmp eq i8 %12, %14
  br i1 %strcmp.cmp6, label %strcmp.loop_null_cmp3, label %pred_false

strcmp.loop_null_cmp:                             ; preds = %entry
  %strcmp.cmp_null = icmp eq i8 %7, 0
  br i1 %strcmp.cmp_null, label %pred_true.critedge, label %strcmp.loop

strcmp.loop2:                                     ; preds = %strcmp.loop_null_cmp3
  %15 = add [64 x i8]* %str, i64 2
  %probe_read10 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %15)
  %16 = load i8, i8* %strcmp.char_l, align 1
  %17 = add [16 x i8]* %comm, i64 2
  %probe_read11 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %17)
  %18 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp12 = icmp eq i8 %16, %18
  br i1 %strcmp.cmp12, label %strcmp.loop_null_cmp9, label %pred_false

strcmp.loop_null_cmp3:                            ; preds = %strcmp.loop
  %strcmp.cmp_null7 = icmp eq i8 %12, 0
  br i1 %strcmp.cmp_null7, label %pred_true.critedge, label %strcmp.loop2

strcmp.loop8:                                     ; preds = %strcmp.loop_null_cmp9
  %19 = add [64 x i8]* %str, i64 3
  %probe_read16 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %19)
  %20 = load i8, i8* %strcmp.char_l, align 1
  %21 = add [16 x i8]* %comm, i64 3
  %probe_read17 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %21)
  %22 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp18 = icmp eq i8 %20, %22
  br i1 %strcmp.cmp18, label %strcmp.loop_null_cmp15, label %pred_false

strcmp.loop_null_cmp9:                            ; preds = %strcmp.loop2
  %strcmp.cmp_null13 = icmp eq i8 %16, 0
  br i1 %strcmp.cmp_null13, label %pred_true.critedge, label %strcmp.loop8

strcmp.loop14:                                    ; preds = %strcmp.loop_null_cmp15
  %23 = add [64 x i8]* %str, i64 4
  %probe_read22 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %23)
  %24 = load i8, i8* %strcmp.char_l, align 1
  %25 = add [16 x i8]* %comm, i64 4
  %probe_read23 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %25)
  %26 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp24 = icmp eq i8 %24, %26
  br i1 %strcmp.cmp24, label %strcmp.loop_null_cmp21, label %pred_false

strcmp.loop_null_cmp15:                           ; preds = %strcmp.loop8
  %strcmp.cmp_null19 = icmp eq i8 %20, 0
  br i1 %strcmp.cmp_null19, label %pred_true.critedge, label %strcmp.loop14

strcmp.loop20:                                    ; preds = %strcmp.loop_null_cmp21
  %27 = add [64 x i8]* %str, i64 5
  %probe_read28 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %27)
  %28 = load i8, i8* %strcmp.char_l, align 1
  %29 = add [16 x i8]* %comm, i64 5
  %probe_read29 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %29)
  %30 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp30 = icmp eq i8 %28, %30
  br i1 %strcmp.cmp30, label %strcmp.loop_null_cmp27, label %pred_false

strcmp.loop_null_cmp21:                           ; preds = %strcmp.loop14
  %strcmp.cmp_null25 = icmp eq i8 %24, 0
  br i1 %strcmp.cmp_null25, label %pred_true.critedge, label %strcmp.loop20

strcmp.loop26:                                    ; preds = %strcmp.loop_null_cmp27
  %31 = add [64 x i8]* %str, i64 6
  %probe_read34 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %31)
  %32 = load i8, i8* %strcmp.char_l, align 1
  %33 = add [16 x i8]* %comm, i64 6
  %probe_read35 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %33)
  %34 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp36 = icmp eq i8 %32, %34
  br i1 %strcmp.cmp36, label %strcmp.loop_null_cmp33, label %pred_false

strcmp.loop_null_cmp27:                           ; preds = %strcmp.loop20
  %strcmp.cmp_null31 = icmp eq i8 %28, 0
  br i1 %strcmp.cmp_null31, label %pred_true.critedge, label %strcmp.loop26

strcmp.loop32:                                    ; preds = %strcmp.loop_null_cmp33
  %35 = add [64 x i8]* %str, i64 7
  %probe_read40 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %35)
  %36 = load i8, i8* %strcmp.char_l, align 1
  %37 = add [16 x i8]* %comm, i64 7
  %probe_read41 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %37)
  %38 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp42 = icmp eq i8 %36, %38
  br i1 %strcmp.cmp42, label %strcmp.loop_null_cmp39, label %pred_false

strcmp.loop_null_cmp33:                           ; preds = %strcmp.loop26
  %strcmp.cmp_null37 = icmp eq i8 %32, 0
  br i1 %strcmp.cmp_null37, label %pred_true.critedge, label %strcmp.loop32

strcmp.loop38:                                    ; preds = %strcmp.loop_null_cmp39
  %39 = add [64 x i8]* %str, i64 8
  %probe_read46 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %39)
  %40 = load i8, i8* %strcmp.char_l, align 1
  %41 = add [16 x i8]* %comm, i64 8
  %probe_read47 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %41)
  %42 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp48 = icmp eq i8 %40, %42
  br i1 %strcmp.cmp48, label %strcmp.loop_null_cmp45, label %pred_false

strcmp.loop_null_cmp39:                           ; preds = %strcmp.loop32
  %strcmp.cmp_null43 = icmp eq i8 %36, 0
  br i1 %strcmp.cmp_null43, label %pred_true.critedge, label %strcmp.loop38

strcmp.loop44:                                    ; preds = %strcmp.loop_null_cmp45
  %43 = add [64 x i8]* %str, i64 9
  %probe_read52 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %43)
  %44 = load i8, i8* %strcmp.char_l, align 1
  %45 = add [16 x i8]* %comm, i64 9
  %probe_read53 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %45)
  %46 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp54 = icmp eq i8 %44, %46
  br i1 %strcmp.cmp54, label %strcmp.loop_null_cmp51, label %pred_false

strcmp.loop_null_cmp45:                           ; preds = %strcmp.loop38
  %strcmp.cmp_null49 = icmp eq i8 %40, 0
  br i1 %strcmp.cmp_null49, label %pred_true.critedge, label %strcmp.loop44

strcmp.loop50:                                    ; preds = %strcmp.loop_null_cmp51
  %47 = add [64 x i8]* %str, i64 10
  %probe_read58 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %47)
  %48 = load i8, i8* %strcmp.char_l, align 1
  %49 = add [16 x i8]* %comm, i64 10
  %probe_read59 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %49)
  %50 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp60 = icmp eq i8 %48, %50
  br i1 %strcmp.cmp60, label %strcmp.loop_null_cmp57, label %pred_false

strcmp.loop_null_cmp51:                           ; preds = %strcmp.loop44
  %strcmp.cmp_null55 = icmp eq i8 %44, 0
  br i1 %strcmp.cmp_null55, label %pred_true.critedge, label %strcmp.loop50

strcmp.loop56:                                    ; preds = %strcmp.loop_null_cmp57
  %51 = add [64 x i8]* %str, i64 11
  %probe_read64 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %51)
  %52 = load i8, i8* %strcmp.char_l, align 1
  %53 = add [16 x i8]* %comm, i64 11
  %probe_read65 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %53)
  %54 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp66 = icmp eq i8 %52, %54
  br i1 %strcmp.cmp66, label %strcmp.loop_null_cmp63, label %pred_false

strcmp.loop_null_cmp57:                           ; preds = %strcmp.loop50
  %strcmp.cmp_null61 = icmp eq i8 %48, 0
  br i1 %strcmp.cmp_null61, label %pred_true.critedge, label %strcmp.loop56

strcmp.loop62:                                    ; preds = %strcmp.loop_null_cmp63
  %55 = add [64 x i8]* %str, i64 12
  %probe_read70 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %55)
  %56 = load i8, i8* %strcmp.char_l, align 1
  %57 = add [16 x i8]* %comm, i64 12
  %probe_read71 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %57)
  %58 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp72 = icmp eq i8 %56, %58
  br i1 %strcmp.cmp72, label %strcmp.loop_null_cmp69, label %pred_false

strcmp.loop_null_cmp63:                           ; preds = %strcmp.loop56
  %strcmp.cmp_null67 = icmp eq i8 %52, 0
  br i1 %strcmp.cmp_null67, label %pred_true.critedge, label %strcmp.loop62

strcmp.loop68:                                    ; preds = %strcmp.loop_null_cmp69
  %59 = add [64 x i8]* %str, i64 13
  %probe_read76 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %59)
  %60 = load i8, i8* %strcmp.char_l, align 1
  %61 = add [16 x i8]* %comm, i64 13
  %probe_read77 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %61)
  %62 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp78 = icmp eq i8 %60, %62
  br i1 %strcmp.cmp78, label %strcmp.loop_null_cmp75, label %pred_false

strcmp.loop_null_cmp69:                           ; preds = %strcmp.loop62
  %strcmp.cmp_null73 = icmp eq i8 %56, 0
  br i1 %strcmp.cmp_null73, label %pred_true.critedge, label %strcmp.loop68

strcmp.loop74:                                    ; preds = %strcmp.loop_null_cmp75
  %63 = add [64 x i8]* %str, i64 14
  %probe_read82 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %63)
  %64 = load i8, i8* %strcmp.char_l, align 1
  %65 = add [16 x i8]* %comm, i64 14
  %probe_read83 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %65)
  %66 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp84 = icmp eq i8 %64, %66
  br i1 %strcmp.cmp84, label %strcmp.loop_null_cmp81, label %pred_false

strcmp.loop_null_cmp75:                           ; preds = %strcmp.loop68
  %strcmp.cmp_null79 = icmp eq i8 %60, 0
  br i1 %strcmp.cmp_null79, label %pred_true.critedge, label %strcmp.loop74

strcmp.loop80:                                    ; preds = %strcmp.loop_null_cmp81
  %67 = add [64 x i8]* %str, i64 15
  %probe_read88 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %67)
  %68 = load i8, i8* %strcmp.char_l, align 1
  %69 = add [16 x i8]* %comm, i64 15
  %probe_read89 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %69)
  %70 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp90 = icmp eq i8 %68, %70
  br i1 %strcmp.cmp90, label %strcmp.loop_null_cmp87, label %pred_false

strcmp.loop_null_cmp81:                           ; preds = %strcmp.loop74
  %strcmp.cmp_null85 = icmp eq i8 %64, 0
  br i1 %strcmp.cmp_null85, label %pred_true.critedge, label %strcmp.loop80

strcmp.loop86:                                    ; preds = %strcmp.loop_null_cmp87
  %71 = add [64 x i8]* %str, i64 16
  %probe_read94 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_l, i64 1, [64 x i8]* %71)
  %72 = load i8, i8* %strcmp.char_l, align 1
  %73 = add [16 x i8]* %comm, i64 16
  %probe_read95 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %strcmp.char_r, i64 1, [16 x i8]* %73)
  %74 = load i8, i8* %strcmp.char_r, align 1
  %strcmp.cmp96 = icmp eq i8 %72, %74
  br i1 %strcmp.cmp96, label %pred_true.critedge, label %pred_false

strcmp.loop_null_cmp87:                           ; preds = %strcmp.loop80
  %strcmp.cmp_null91 = icmp eq i8 %68, 0
  br i1 %strcmp.cmp_null91, label %pred_true.critedge, label %strcmp.loop86
}

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i1 immarg) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64 immarg, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
