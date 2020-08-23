; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

%helper_error_t = type <{ i64, i64, i32, i8 }>
%printf_t = type { i64, i64 }
%printf_t.0 = type { i64, i64 }
%printf_t.1 = type { i64, i64 }
%printf_t.2 = type { i64, i64 }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

define i64 @BEGIN(i8*) section "s_BEGIN_1" {
entry:
  %helper_error_t29 = alloca %helper_error_t
  %lookup_fmtstr_key24 = alloca i32
  %helper_error_t19 = alloca %helper_error_t
  %lookup_fmtstr_key14 = alloca i32
  %helper_error_t9 = alloca %helper_error_t
  %lookup_fmtstr_key4 = alloca i32
  %helper_error_t = alloca %helper_error_t
  %lookup_fmtstr_key = alloca i32
  %"$x" = alloca i64
  %1 = bitcast i64* %"$x" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 0, i64* %"$x"
  %2 = bitcast i64* %"$x" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %2)
  store i64 10, i64* %"$x"
  %3 = bitcast i32* %lookup_fmtstr_key to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %3)
  store i32 0, i32* %lookup_fmtstr_key
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  %lookup_fmtstr_map = call %printf_t* inttoptr (i64 1 to %printf_t* (i64, i32*)*)(i64 %pseudo, i32* %lookup_fmtstr_key)
  %4 = bitcast i32* %lookup_fmtstr_key to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %4)
  %5 = sext %printf_t* %lookup_fmtstr_map to i32
  %6 = icmp ne i32 %5, 0
  br i1 %6, label %helper_merge, label %helper_failure

helper_failure:                                   ; preds = %entry
  %7 = bitcast %helper_error_t* %helper_error_t to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %7)
  %8 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 0
  store i64 30006, i64* %8
  %9 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 1
  store i64 0, i64* %9
  %10 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 2
  store i32 %5, i32* %10
  %11 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 3
  store i8 1, i8* %11
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %helper_error_t*, i64)*)(i8* %0, i64 %pseudo1, i64 4294967295, %helper_error_t* %helper_error_t, i64 21)
  %12 = bitcast %helper_error_t* %helper_error_t to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %12)
  ret i64 0

helper_merge:                                     ; preds = %entry
  %13 = bitcast %printf_t* %lookup_fmtstr_map to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %13, i8 0, i64 16, i1 false)
  %14 = getelementptr %printf_t, %printf_t* %lookup_fmtstr_map, i32 0, i32 0
  store i64 0, i64* %14
  %15 = load i64, i64* %"$x"
  %16 = add i64 %15, 1
  store i64 %16, i64* %"$x"
  %17 = getelementptr %printf_t, %printf_t* %lookup_fmtstr_map, i32 0, i32 1
  store i64 %15, i64* %17
  %pseudo2 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %perf_event_output3 = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %printf_t*, i64)*)(i8* %0, i64 %pseudo2, i64 4294967295, %printf_t* %lookup_fmtstr_map, i64 16)
  %18 = bitcast i32* %lookup_fmtstr_key4 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %18)
  store i32 0, i32* %lookup_fmtstr_key4
  %pseudo5 = call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  %lookup_fmtstr_map6 = call %printf_t.0* inttoptr (i64 1 to %printf_t.0* (i64, i32*)*)(i64 %pseudo5, i32* %lookup_fmtstr_key4)
  %19 = bitcast i32* %lookup_fmtstr_key4 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %19)
  %20 = sext %printf_t.0* %lookup_fmtstr_map6 to i32
  %21 = icmp ne i32 %20, 0
  br i1 %21, label %helper_merge8, label %helper_failure7

helper_failure7:                                  ; preds = %helper_merge
  %22 = bitcast %helper_error_t* %helper_error_t9 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %22)
  %23 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t9, i64 0, i32 0
  store i64 30006, i64* %23
  %24 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t9, i64 0, i32 1
  store i64 1, i64* %24
  %25 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t9, i64 0, i32 2
  store i32 %20, i32* %25
  %26 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t9, i64 0, i32 3
  store i8 1, i8* %26
  %pseudo10 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %perf_event_output11 = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %helper_error_t*, i64)*)(i8* %0, i64 %pseudo10, i64 4294967295, %helper_error_t* %helper_error_t9, i64 21)
  %27 = bitcast %helper_error_t* %helper_error_t9 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %27)
  ret i64 0

helper_merge8:                                    ; preds = %helper_merge
  %28 = bitcast %printf_t.0* %lookup_fmtstr_map6 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %28, i8 0, i64 16, i1 false)
  %29 = getelementptr %printf_t.0, %printf_t.0* %lookup_fmtstr_map6, i32 0, i32 0
  store i64 1, i64* %29
  %30 = load i64, i64* %"$x"
  %31 = add i64 %30, 1
  store i64 %31, i64* %"$x"
  %32 = getelementptr %printf_t.0, %printf_t.0* %lookup_fmtstr_map6, i32 0, i32 1
  store i64 %31, i64* %32
  %pseudo12 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %perf_event_output13 = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %printf_t.0*, i64)*)(i8* %0, i64 %pseudo12, i64 4294967295, %printf_t.0* %lookup_fmtstr_map6, i64 16)
  %33 = bitcast i32* %lookup_fmtstr_key14 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %33)
  store i32 0, i32* %lookup_fmtstr_key14
  %pseudo15 = call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  %lookup_fmtstr_map16 = call %printf_t.1* inttoptr (i64 1 to %printf_t.1* (i64, i32*)*)(i64 %pseudo15, i32* %lookup_fmtstr_key14)
  %34 = bitcast i32* %lookup_fmtstr_key14 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %34)
  %35 = sext %printf_t.1* %lookup_fmtstr_map16 to i32
  %36 = icmp ne i32 %35, 0
  br i1 %36, label %helper_merge18, label %helper_failure17

helper_failure17:                                 ; preds = %helper_merge8
  %37 = bitcast %helper_error_t* %helper_error_t19 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %37)
  %38 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t19, i64 0, i32 0
  store i64 30006, i64* %38
  %39 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t19, i64 0, i32 1
  store i64 2, i64* %39
  %40 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t19, i64 0, i32 2
  store i32 %35, i32* %40
  %41 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t19, i64 0, i32 3
  store i8 1, i8* %41
  %pseudo20 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %perf_event_output21 = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %helper_error_t*, i64)*)(i8* %0, i64 %pseudo20, i64 4294967295, %helper_error_t* %helper_error_t19, i64 21)
  %42 = bitcast %helper_error_t* %helper_error_t19 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %42)
  ret i64 0

helper_merge18:                                   ; preds = %helper_merge8
  %43 = bitcast %printf_t.1* %lookup_fmtstr_map16 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %43, i8 0, i64 16, i1 false)
  %44 = getelementptr %printf_t.1, %printf_t.1* %lookup_fmtstr_map16, i32 0, i32 0
  store i64 2, i64* %44
  %45 = load i64, i64* %"$x"
  %46 = sub i64 %45, 1
  store i64 %46, i64* %"$x"
  %47 = getelementptr %printf_t.1, %printf_t.1* %lookup_fmtstr_map16, i32 0, i32 1
  store i64 %45, i64* %47
  %pseudo22 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %perf_event_output23 = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %printf_t.1*, i64)*)(i8* %0, i64 %pseudo22, i64 4294967295, %printf_t.1* %lookup_fmtstr_map16, i64 16)
  %48 = bitcast i32* %lookup_fmtstr_key24 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %48)
  store i32 0, i32* %lookup_fmtstr_key24
  %pseudo25 = call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  %lookup_fmtstr_map26 = call %printf_t.2* inttoptr (i64 1 to %printf_t.2* (i64, i32*)*)(i64 %pseudo25, i32* %lookup_fmtstr_key24)
  %49 = bitcast i32* %lookup_fmtstr_key24 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %49)
  %50 = sext %printf_t.2* %lookup_fmtstr_map26 to i32
  %51 = icmp ne i32 %50, 0
  br i1 %51, label %helper_merge28, label %helper_failure27

helper_failure27:                                 ; preds = %helper_merge18
  %52 = bitcast %helper_error_t* %helper_error_t29 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %52)
  %53 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t29, i64 0, i32 0
  store i64 30006, i64* %53
  %54 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t29, i64 0, i32 1
  store i64 3, i64* %54
  %55 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t29, i64 0, i32 2
  store i32 %50, i32* %55
  %56 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t29, i64 0, i32 3
  store i8 1, i8* %56
  %pseudo30 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %perf_event_output31 = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %helper_error_t*, i64)*)(i8* %0, i64 %pseudo30, i64 4294967295, %helper_error_t* %helper_error_t29, i64 21)
  %57 = bitcast %helper_error_t* %helper_error_t29 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %57)
  ret i64 0

helper_merge28:                                   ; preds = %helper_merge18
  %58 = bitcast %printf_t.2* %lookup_fmtstr_map26 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %58, i8 0, i64 16, i1 false)
  %59 = getelementptr %printf_t.2, %printf_t.2* %lookup_fmtstr_map26, i32 0, i32 0
  store i64 3, i64* %59
  %60 = load i64, i64* %"$x"
  %61 = sub i64 %60, 1
  store i64 %61, i64* %"$x"
  %62 = getelementptr %printf_t.2, %printf_t.2* %lookup_fmtstr_map26, i32 0, i32 1
  store i64 %61, i64* %62
  %pseudo32 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %perf_event_output33 = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %printf_t.2*, i64)*)(i8* %0, i64 %pseudo32, i64 4294967295, %printf_t.2* %lookup_fmtstr_map26, i64 16)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
