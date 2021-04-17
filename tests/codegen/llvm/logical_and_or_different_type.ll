; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

%printf_t = type { i64, i64, i64, i64, i64 }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

define i64 @BEGIN(i8*) section "s_BEGIN_1" {
entry:
  %"struct Foo.m16" = alloca i32
  %"||_result15" = alloca i64
  %"struct Foo.m8" = alloca i32
  %"||_result" = alloca i64
  %"struct Foo.m6" = alloca i32
  %"&&_result5" = alloca i64
  %"struct Foo.m" = alloca i32
  %"&&_result" = alloca i64
  %printf_args = alloca %printf_t
  %"$foo" = alloca i64
  %1 = bitcast i64* %"$foo" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 0, i64* %"$foo"
  %2 = bitcast i8* %0 to i64*
  %3 = getelementptr i64, i64* %2, i64 14
  %arg0 = load volatile i64, i64* %3
  %4 = bitcast i64* %"$foo" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %4)
  store i64 %arg0, i64* %"$foo"
  %5 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %5)
  %6 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %6, i8 0, i64 40, i1 false)
  %7 = getelementptr %printf_t, %printf_t* %printf_args, i32 0, i32 0
  store i64 0, i64* %7
  %8 = bitcast i64* %"&&_result" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %8)
  %9 = load i64, i64* %"$foo"
  %10 = add i64 %9, 0
  %11 = bitcast i32* %"struct Foo.m" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %11)
  %probe_read_user = call i64 inttoptr (i64 112 to i64 (i32*, i32, i64)*)(i32* %"struct Foo.m", i32 4, i64 %10)
  %12 = load i32, i32* %"struct Foo.m"
  %13 = sext i32 %12 to i64
  %14 = bitcast i32* %"struct Foo.m" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %14)
  %lhs_true_cond = icmp ne i64 %13, 0
  br i1 %lhs_true_cond, label %"&&_lhs_true", label %"&&_false"

"&&_lhs_true":                                    ; preds = %entry
  br i1 false, label %"&&_true", label %"&&_false"

"&&_true":                                        ; preds = %"&&_lhs_true"
  store i64 1, i64* %"&&_result"
  br label %"&&_merge"

"&&_false":                                       ; preds = %"&&_lhs_true", %entry
  store i64 0, i64* %"&&_result"
  br label %"&&_merge"

"&&_merge":                                       ; preds = %"&&_false", %"&&_true"
  %15 = load i64, i64* %"&&_result"
  %16 = getelementptr %printf_t, %printf_t* %printf_args, i32 0, i32 1
  store i64 %15, i64* %16
  %17 = bitcast i64* %"&&_result5" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %17)
  br i1 true, label %"&&_lhs_true1", label %"&&_false3"

"&&_lhs_true1":                                   ; preds = %"&&_merge"
  %18 = load i64, i64* %"$foo"
  %19 = add i64 %18, 0
  %20 = bitcast i32* %"struct Foo.m6" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %20)
  %probe_read_user7 = call i64 inttoptr (i64 112 to i64 (i32*, i32, i64)*)(i32* %"struct Foo.m6", i32 4, i64 %19)
  %21 = load i32, i32* %"struct Foo.m6"
  %22 = sext i32 %21 to i64
  %23 = bitcast i32* %"struct Foo.m6" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %23)
  %rhs_true_cond = icmp ne i64 %22, 0
  br i1 %rhs_true_cond, label %"&&_true2", label %"&&_false3"

"&&_true2":                                       ; preds = %"&&_lhs_true1"
  store i64 1, i64* %"&&_result5"
  br label %"&&_merge4"

"&&_false3":                                      ; preds = %"&&_lhs_true1", %"&&_merge"
  store i64 0, i64* %"&&_result5"
  br label %"&&_merge4"

"&&_merge4":                                      ; preds = %"&&_false3", %"&&_true2"
  %24 = load i64, i64* %"&&_result5"
  %25 = getelementptr %printf_t, %printf_t* %printf_args, i32 0, i32 2
  store i64 %24, i64* %25
  %26 = bitcast i64* %"||_result" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %26)
  %27 = load i64, i64* %"$foo"
  %28 = add i64 %27, 0
  %29 = bitcast i32* %"struct Foo.m8" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %29)
  %probe_read_user9 = call i64 inttoptr (i64 112 to i64 (i32*, i32, i64)*)(i32* %"struct Foo.m8", i32 4, i64 %28)
  %30 = load i32, i32* %"struct Foo.m8"
  %31 = sext i32 %30 to i64
  %32 = bitcast i32* %"struct Foo.m8" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %32)
  %lhs_true_cond10 = icmp ne i64 %31, 0
  br i1 %lhs_true_cond10, label %"||_true", label %"||_lhs_false"

"||_lhs_false":                                   ; preds = %"&&_merge4"
  br i1 false, label %"||_true", label %"||_false"

"||_false":                                       ; preds = %"||_lhs_false"
  store i64 0, i64* %"||_result"
  br label %"||_merge"

"||_true":                                        ; preds = %"||_lhs_false", %"&&_merge4"
  store i64 1, i64* %"||_result"
  br label %"||_merge"

"||_merge":                                       ; preds = %"||_true", %"||_false"
  %33 = load i64, i64* %"||_result"
  %34 = getelementptr %printf_t, %printf_t* %printf_args, i32 0, i32 3
  store i64 %33, i64* %34
  %35 = bitcast i64* %"||_result15" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %35)
  br i1 false, label %"||_true13", label %"||_lhs_false11"

"||_lhs_false11":                                 ; preds = %"||_merge"
  %36 = load i64, i64* %"$foo"
  %37 = add i64 %36, 0
  %38 = bitcast i32* %"struct Foo.m16" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %38)
  %probe_read_user17 = call i64 inttoptr (i64 112 to i64 (i32*, i32, i64)*)(i32* %"struct Foo.m16", i32 4, i64 %37)
  %39 = load i32, i32* %"struct Foo.m16"
  %40 = sext i32 %39 to i64
  %41 = bitcast i32* %"struct Foo.m16" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %41)
  %rhs_true_cond18 = icmp ne i64 %40, 0
  br i1 %rhs_true_cond18, label %"||_true13", label %"||_false12"

"||_false12":                                     ; preds = %"||_lhs_false11"
  store i64 0, i64* %"||_result15"
  br label %"||_merge14"

"||_true13":                                      ; preds = %"||_lhs_false11", %"||_merge"
  store i64 1, i64* %"||_result15"
  br label %"||_merge14"

"||_merge14":                                     ; preds = %"||_true13", %"||_false12"
  %42 = load i64, i64* %"||_result15"
  %43 = getelementptr %printf_t, %printf_t* %printf_args, i32 0, i32 4
  store i64 %42, i64* %43
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %printf_t*, i64)*)(i8* %0, i64 %pseudo, i64 4294967295, %printf_t* %printf_args, i64 40)
  %44 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %44)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i1) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
