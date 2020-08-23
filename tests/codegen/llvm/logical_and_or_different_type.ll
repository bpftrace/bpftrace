; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

%helper_error_t = type <{ i64, i64, i32, i8 }>
%printf_t = type { i64, i64, i64, i64, i64 }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

define i64 @BEGIN(i8*) section "s_BEGIN_1" {
entry:
  %"struct Foo.m23" = alloca i32
  %"||_result22" = alloca i64
  %"struct Foo.m15" = alloca i32
  %"||_result" = alloca i64
  %"struct Foo.m13" = alloca i32
  %"&&_result12" = alloca i64
  %"struct Foo.m" = alloca i32
  %"&&_result" = alloca i64
  %helper_error_t5 = alloca %helper_error_t
  %lookup_fmtstr_key = alloca i32
  %helper_error_t = alloca %helper_error_t
  %"lookup_$foo_key" = alloca i32
  %1 = bitcast i32* %"lookup_$foo_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i32 0, i32* %"lookup_$foo_key"
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %"lookup_$foo_map" = call [4 x i8]* inttoptr (i64 1 to [4 x i8]* (i64, i32*)*)(i64 %pseudo, i32* %"lookup_$foo_key")
  %2 = bitcast i32* %"lookup_$foo_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %2)
  %3 = sext [4 x i8]* %"lookup_$foo_map" to i32
  %4 = icmp ne i32 %3, 0
  br i1 %4, label %helper_merge, label %helper_failure

helper_failure:                                   ; preds = %entry
  %5 = bitcast %helper_error_t* %helper_error_t to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %5)
  %6 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 0
  store i64 30006, i64* %6
  %7 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 1
  store i64 0, i64* %7
  %8 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 2
  store i32 %3, i32* %8
  %9 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 3
  store i8 1, i8* %9
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %helper_error_t*, i64)*)(i8* %0, i64 %pseudo1, i64 4294967295, %helper_error_t* %helper_error_t, i64 21)
  %10 = bitcast %helper_error_t* %helper_error_t to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %10)
  ret i64 0

helper_merge:                                     ; preds = %entry
  %11 = bitcast [4 x i8]* %"lookup_$foo_map" to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %11, i8 0, i64 4, i1 false)
  %12 = bitcast [4 x i8]* %"lookup_$foo_map" to i8*
  %13 = bitcast i64 0 to i8 addrspace(64)*
  call void @llvm.memcpy.p0i8.p64i8.i64(i8* align 1 %12, i8 addrspace(64)* align 1 %13, i64 4, i1 false)
  %14 = bitcast i32* %lookup_fmtstr_key to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %14)
  store i32 0, i32* %lookup_fmtstr_key
  %pseudo2 = call i64 @llvm.bpf.pseudo(i64 1, i64 3)
  %lookup_fmtstr_map = call %printf_t* inttoptr (i64 1 to %printf_t* (i64, i32*)*)(i64 %pseudo2, i32* %lookup_fmtstr_key)
  %15 = bitcast i32* %lookup_fmtstr_key to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %15)
  %16 = sext %printf_t* %lookup_fmtstr_map to i32
  %17 = icmp ne i32 %16, 0
  br i1 %17, label %helper_merge4, label %helper_failure3

helper_failure3:                                  ; preds = %helper_merge
  %18 = bitcast %helper_error_t* %helper_error_t5 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %18)
  %19 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t5, i64 0, i32 0
  store i64 30006, i64* %19
  %20 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t5, i64 0, i32 1
  store i64 1, i64* %20
  %21 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t5, i64 0, i32 2
  store i32 %16, i32* %21
  %22 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t5, i64 0, i32 3
  store i8 1, i8* %22
  %pseudo6 = call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  %perf_event_output7 = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %helper_error_t*, i64)*)(i8* %0, i64 %pseudo6, i64 4294967295, %helper_error_t* %helper_error_t5, i64 21)
  %23 = bitcast %helper_error_t* %helper_error_t5 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %23)
  ret i64 0

helper_merge4:                                    ; preds = %helper_merge
  %24 = bitcast %printf_t* %lookup_fmtstr_map to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %24, i8 0, i64 40, i1 false)
  %25 = getelementptr %printf_t, %printf_t* %lookup_fmtstr_map, i32 0, i32 0
  store i64 0, i64* %25
  %26 = bitcast i64* %"&&_result" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %26)
  %27 = add [4 x i8]* %"lookup_$foo_map", i64 0
  %28 = bitcast i32* %"struct Foo.m" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %28)
  %probe_read = call i64 inttoptr (i64 4 to i64 (i32*, i32, [4 x i8]*)*)(i32* %"struct Foo.m", i32 4, [4 x i8]* %27)
  %29 = load i32, i32* %"struct Foo.m"
  %30 = sext i32 %29 to i64
  %31 = bitcast i32* %"struct Foo.m" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %31)
  %lhs_true_cond = icmp ne i64 %30, 0
  br i1 %lhs_true_cond, label %"&&_lhs_true", label %"&&_false"

"&&_lhs_true":                                    ; preds = %helper_merge4
  br i1 false, label %"&&_true", label %"&&_false"

"&&_true":                                        ; preds = %"&&_lhs_true"
  store i64 1, i64* %"&&_result"
  br label %"&&_merge"

"&&_false":                                       ; preds = %"&&_lhs_true", %helper_merge4
  store i64 0, i64* %"&&_result"
  br label %"&&_merge"

"&&_merge":                                       ; preds = %"&&_false", %"&&_true"
  %32 = load i64, i64* %"&&_result"
  %33 = getelementptr %printf_t, %printf_t* %lookup_fmtstr_map, i32 0, i32 1
  store i64 %32, i64* %33
  %34 = bitcast i64* %"&&_result12" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %34)
  br i1 true, label %"&&_lhs_true8", label %"&&_false10"

"&&_lhs_true8":                                   ; preds = %"&&_merge"
  %35 = add [4 x i8]* %"lookup_$foo_map", i64 0
  %36 = bitcast i32* %"struct Foo.m13" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %36)
  %probe_read14 = call i64 inttoptr (i64 4 to i64 (i32*, i32, [4 x i8]*)*)(i32* %"struct Foo.m13", i32 4, [4 x i8]* %35)
  %37 = load i32, i32* %"struct Foo.m13"
  %38 = sext i32 %37 to i64
  %39 = bitcast i32* %"struct Foo.m13" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %39)
  %rhs_true_cond = icmp ne i64 %38, 0
  br i1 %rhs_true_cond, label %"&&_true9", label %"&&_false10"

"&&_true9":                                       ; preds = %"&&_lhs_true8"
  store i64 1, i64* %"&&_result12"
  br label %"&&_merge11"

"&&_false10":                                     ; preds = %"&&_lhs_true8", %"&&_merge"
  store i64 0, i64* %"&&_result12"
  br label %"&&_merge11"

"&&_merge11":                                     ; preds = %"&&_false10", %"&&_true9"
  %40 = load i64, i64* %"&&_result12"
  %41 = getelementptr %printf_t, %printf_t* %lookup_fmtstr_map, i32 0, i32 2
  store i64 %40, i64* %41
  %42 = bitcast i64* %"||_result" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %42)
  %43 = add [4 x i8]* %"lookup_$foo_map", i64 0
  %44 = bitcast i32* %"struct Foo.m15" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %44)
  %probe_read16 = call i64 inttoptr (i64 4 to i64 (i32*, i32, [4 x i8]*)*)(i32* %"struct Foo.m15", i32 4, [4 x i8]* %43)
  %45 = load i32, i32* %"struct Foo.m15"
  %46 = sext i32 %45 to i64
  %47 = bitcast i32* %"struct Foo.m15" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %47)
  %lhs_true_cond17 = icmp ne i64 %46, 0
  br i1 %lhs_true_cond17, label %"||_true", label %"||_lhs_false"

"||_lhs_false":                                   ; preds = %"&&_merge11"
  br i1 false, label %"||_true", label %"||_false"

"||_false":                                       ; preds = %"||_lhs_false"
  store i64 0, i64* %"||_result"
  br label %"||_merge"

"||_true":                                        ; preds = %"||_lhs_false", %"&&_merge11"
  store i64 1, i64* %"||_result"
  br label %"||_merge"

"||_merge":                                       ; preds = %"||_true", %"||_false"
  %48 = load i64, i64* %"||_result"
  %49 = getelementptr %printf_t, %printf_t* %lookup_fmtstr_map, i32 0, i32 3
  store i64 %48, i64* %49
  %50 = bitcast i64* %"||_result22" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %50)
  br i1 false, label %"||_true20", label %"||_lhs_false18"

"||_lhs_false18":                                 ; preds = %"||_merge"
  %51 = add [4 x i8]* %"lookup_$foo_map", i64 0
  %52 = bitcast i32* %"struct Foo.m23" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %52)
  %probe_read24 = call i64 inttoptr (i64 4 to i64 (i32*, i32, [4 x i8]*)*)(i32* %"struct Foo.m23", i32 4, [4 x i8]* %51)
  %53 = load i32, i32* %"struct Foo.m23"
  %54 = sext i32 %53 to i64
  %55 = bitcast i32* %"struct Foo.m23" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %55)
  %rhs_true_cond25 = icmp ne i64 %54, 0
  br i1 %rhs_true_cond25, label %"||_true20", label %"||_false19"

"||_false19":                                     ; preds = %"||_lhs_false18"
  store i64 0, i64* %"||_result22"
  br label %"||_merge21"

"||_true20":                                      ; preds = %"||_lhs_false18", %"||_merge"
  store i64 1, i64* %"||_result22"
  br label %"||_merge21"

"||_merge21":                                     ; preds = %"||_true20", %"||_false19"
  %56 = load i64, i64* %"||_result22"
  %57 = getelementptr %printf_t, %printf_t* %lookup_fmtstr_map, i32 0, i32 4
  store i64 %56, i64* %57
  %pseudo26 = call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  %perf_event_output27 = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %printf_t*, i64)*)(i8* %0, i64 %pseudo26, i64 4294967295, %printf_t* %lookup_fmtstr_map, i64 40)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i1) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.memcpy.p0i8.p64i8.i64(i8* nocapture writeonly, i8 addrspace(64)* nocapture readonly, i64, i1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
