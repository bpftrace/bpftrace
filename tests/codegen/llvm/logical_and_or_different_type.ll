; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%helper_error_t = type <{ i64, i64, i32, i8 }>
%printf_t = type { i64, i64, i64, i64, i64 }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @BEGIN(i8* %0) section "s_BEGIN_1" {
entry:
  %"struct Foo.m17" = alloca i32, align 4
  %"||_result16" = alloca i64, align 8
  %"struct Foo.m9" = alloca i32, align 4
  %"||_result" = alloca i64, align 8
  %"struct Foo.m7" = alloca i32, align 4
  %"&&_result6" = alloca i64, align 8
  %"struct Foo.m" = alloca i32, align 4
  %"&&_result" = alloca i64, align 8
  %helper_error_t = alloca %helper_error_t, align 8
  %lookup_fmtstr_key = alloca i32, align 4
  %"$foo" = alloca i64, align 8
  %1 = bitcast i64* %"$foo" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 0, i64* %"$foo", align 8
  br label %validate_map_lookup_fmtstr

validate_map_lookup_fmtstr:                       ; preds = %entry
  %2 = bitcast i32* %lookup_fmtstr_key to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %2)
  store i32 0, i32* %lookup_fmtstr_key, align 4
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %lookup_fmtstr_map = call %printf_t* inttoptr (i64 1 to %printf_t* (i64, i32*)*)(i64 %pseudo, i32* %lookup_fmtstr_key)
  %3 = bitcast i32* %lookup_fmtstr_key to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %3)
  %4 = sext %printf_t* %lookup_fmtstr_map to i32
  %5 = icmp ne i32 %4, 0
  br i1 %5, label %post_hoist, label %lookup_fmtstr_map_validate_failure

post_hoist:                                       ; preds = %validate_map_lookup_fmtstr
  %6 = bitcast i8* %0 to i64*
  %7 = getelementptr i64, i64* %6, i64 14
  %arg0 = load volatile i64, i64* %7, align 8
  store i64 %arg0, i64* %"$foo", align 8
  %8 = bitcast %printf_t* %lookup_fmtstr_map to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %8, i8 0, i64 40, i1 false)
  %9 = getelementptr %printf_t, %printf_t* %lookup_fmtstr_map, i32 0, i32 0
  store i64 0, i64* %9, align 8
  %10 = bitcast i64* %"&&_result" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %10)
  %11 = load i64, i64* %"$foo", align 8
  %12 = add i64 %11, 0
  %13 = bitcast i32* %"struct Foo.m" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %13)
  %probe_read_user = call i64 inttoptr (i64 112 to i64 (i32*, i32, i64)*)(i32* %"struct Foo.m", i32 4, i64 %12)
  %14 = load i32, i32* %"struct Foo.m", align 4
  %15 = sext i32 %14 to i64
  %16 = bitcast i32* %"struct Foo.m" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %16)
  %lhs_true_cond = icmp ne i64 %15, 0
  br i1 %lhs_true_cond, label %"&&_lhs_true", label %"&&_false"

lookup_fmtstr_map_validate_failure:               ; preds = %validate_map_lookup_fmtstr
  %17 = bitcast %helper_error_t* %helper_error_t to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %17)
  %18 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 0
  store i64 30006, i64* %18, align 8
  %19 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 1
  store i64 0, i64* %19, align 8
  %20 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 2
  store i32 %4, i32* %20, align 4
  %21 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 3
  store i8 1, i8* %21, align 1
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %helper_error_t*, i64)*)(i8* %0, i64 %pseudo1, i64 4294967295, %helper_error_t* %helper_error_t, i64 21)
  %22 = bitcast %helper_error_t* %helper_error_t to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %22)
  ret i64 0

"&&_lhs_true":                                    ; preds = %post_hoist
  br i1 false, label %"&&_true", label %"&&_false"

"&&_true":                                        ; preds = %"&&_lhs_true"
  store i64 1, i64* %"&&_result", align 8
  br label %"&&_merge"

"&&_false":                                       ; preds = %"&&_lhs_true", %post_hoist
  store i64 0, i64* %"&&_result", align 8
  br label %"&&_merge"

"&&_merge":                                       ; preds = %"&&_false", %"&&_true"
  %23 = load i64, i64* %"&&_result", align 8
  %24 = getelementptr %printf_t, %printf_t* %lookup_fmtstr_map, i32 0, i32 1
  store i64 %23, i64* %24, align 8
  %25 = bitcast i64* %"&&_result6" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %25)
  br i1 true, label %"&&_lhs_true2", label %"&&_false4"

"&&_lhs_true2":                                   ; preds = %"&&_merge"
  %26 = load i64, i64* %"$foo", align 8
  %27 = add i64 %26, 0
  %28 = bitcast i32* %"struct Foo.m7" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %28)
  %probe_read_user8 = call i64 inttoptr (i64 112 to i64 (i32*, i32, i64)*)(i32* %"struct Foo.m7", i32 4, i64 %27)
  %29 = load i32, i32* %"struct Foo.m7", align 4
  %30 = sext i32 %29 to i64
  %31 = bitcast i32* %"struct Foo.m7" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %31)
  %rhs_true_cond = icmp ne i64 %30, 0
  br i1 %rhs_true_cond, label %"&&_true3", label %"&&_false4"

"&&_true3":                                       ; preds = %"&&_lhs_true2"
  store i64 1, i64* %"&&_result6", align 8
  br label %"&&_merge5"

"&&_false4":                                      ; preds = %"&&_lhs_true2", %"&&_merge"
  store i64 0, i64* %"&&_result6", align 8
  br label %"&&_merge5"

"&&_merge5":                                      ; preds = %"&&_false4", %"&&_true3"
  %32 = load i64, i64* %"&&_result6", align 8
  %33 = getelementptr %printf_t, %printf_t* %lookup_fmtstr_map, i32 0, i32 2
  store i64 %32, i64* %33, align 8
  %34 = bitcast i64* %"||_result" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %34)
  %35 = load i64, i64* %"$foo", align 8
  %36 = add i64 %35, 0
  %37 = bitcast i32* %"struct Foo.m9" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %37)
  %probe_read_user10 = call i64 inttoptr (i64 112 to i64 (i32*, i32, i64)*)(i32* %"struct Foo.m9", i32 4, i64 %36)
  %38 = load i32, i32* %"struct Foo.m9", align 4
  %39 = sext i32 %38 to i64
  %40 = bitcast i32* %"struct Foo.m9" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %40)
  %lhs_true_cond11 = icmp ne i64 %39, 0
  br i1 %lhs_true_cond11, label %"||_true", label %"||_lhs_false"

"||_lhs_false":                                   ; preds = %"&&_merge5"
  br i1 false, label %"||_true", label %"||_false"

"||_false":                                       ; preds = %"||_lhs_false"
  store i64 0, i64* %"||_result", align 8
  br label %"||_merge"

"||_true":                                        ; preds = %"||_lhs_false", %"&&_merge5"
  store i64 1, i64* %"||_result", align 8
  br label %"||_merge"

"||_merge":                                       ; preds = %"||_true", %"||_false"
  %41 = load i64, i64* %"||_result", align 8
  %42 = getelementptr %printf_t, %printf_t* %lookup_fmtstr_map, i32 0, i32 3
  store i64 %41, i64* %42, align 8
  %43 = bitcast i64* %"||_result16" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %43)
  br i1 false, label %"||_true14", label %"||_lhs_false12"

"||_lhs_false12":                                 ; preds = %"||_merge"
  %44 = load i64, i64* %"$foo", align 8
  %45 = add i64 %44, 0
  %46 = bitcast i32* %"struct Foo.m17" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %46)
  %probe_read_user18 = call i64 inttoptr (i64 112 to i64 (i32*, i32, i64)*)(i32* %"struct Foo.m17", i32 4, i64 %45)
  %47 = load i32, i32* %"struct Foo.m17", align 4
  %48 = sext i32 %47 to i64
  %49 = bitcast i32* %"struct Foo.m17" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %49)
  %rhs_true_cond19 = icmp ne i64 %48, 0
  br i1 %rhs_true_cond19, label %"||_true14", label %"||_false13"

"||_false13":                                     ; preds = %"||_lhs_false12"
  store i64 0, i64* %"||_result16", align 8
  br label %"||_merge15"

"||_true14":                                      ; preds = %"||_lhs_false12", %"||_merge"
  store i64 1, i64* %"||_result16", align 8
  br label %"||_merge15"

"||_merge15":                                     ; preds = %"||_true14", %"||_false13"
  %50 = load i64, i64* %"||_result16", align 8
  %51 = getelementptr %printf_t, %printf_t* %lookup_fmtstr_map, i32 0, i32 4
  store i64 %50, i64* %51, align 8
  %pseudo20 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %perf_event_output21 = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %printf_t*, i64)*)(i8* %0, i64 %pseudo20, i64 4294967295, %printf_t* %lookup_fmtstr_map, i64 40)
  ret i64 0
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn writeonly
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }
attributes #2 = { argmemonly nofree nosync nounwind willreturn writeonly }
