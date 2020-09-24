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
  %"$foo" = alloca [4 x i8]
  %1 = bitcast [4 x i8]* %"$foo" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  %2 = bitcast [4 x i8]* %"$foo" to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %2, i8 0, i64 4, i1 false)
  %3 = bitcast i8* %0 to i64*
  %4 = getelementptr i64, i64* %3, i64 14
  %arg0 = load volatile i64, i64* %4
  %5 = bitcast [4 x i8]* %"$foo" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %5)
  %6 = bitcast [4 x i8]* %"$foo" to i8*
  %7 = bitcast i64 %arg0 to i8 addrspace(64)*
  call void @llvm.memcpy.p0i8.p64i8.i64(i8* align 1 %6, i8 addrspace(64)* align 1 %7, i64 4, i1 false)
  %8 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %8)
  %9 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %9, i8 0, i64 40, i1 false)
  %10 = getelementptr %printf_t, %printf_t* %printf_args, i32 0, i32 0
  store i64 0, i64* %10
  %11 = bitcast i64* %"&&_result" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %11)
  %12 = add [4 x i8]* %"$foo", i64 0
  %13 = bitcast i32* %"struct Foo.m" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %13)
  %probe_read_user = call i64 inttoptr (i64 112 to i64 (i32*, i32, [4 x i8]*)*)(i32* %"struct Foo.m", i32 4, [4 x i8]* %12)
  %14 = load i32, i32* %"struct Foo.m"
  %15 = sext i32 %14 to i64
  %16 = bitcast i32* %"struct Foo.m" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %16)
  %lhs_true_cond = icmp ne i64 %15, 0
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
  %17 = load i64, i64* %"&&_result"
  %18 = getelementptr %printf_t, %printf_t* %printf_args, i32 0, i32 1
  store i64 %17, i64* %18
  %19 = bitcast i64* %"&&_result5" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %19)
  br i1 true, label %"&&_lhs_true1", label %"&&_false3"

"&&_lhs_true1":                                   ; preds = %"&&_merge"
  %20 = add [4 x i8]* %"$foo", i64 0
  %21 = bitcast i32* %"struct Foo.m6" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %21)
  %probe_read_user7 = call i64 inttoptr (i64 112 to i64 (i32*, i32, [4 x i8]*)*)(i32* %"struct Foo.m6", i32 4, [4 x i8]* %20)
  %22 = load i32, i32* %"struct Foo.m6"
  %23 = sext i32 %22 to i64
  %24 = bitcast i32* %"struct Foo.m6" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %24)
  %rhs_true_cond = icmp ne i64 %23, 0
  br i1 %rhs_true_cond, label %"&&_true2", label %"&&_false3"

"&&_true2":                                       ; preds = %"&&_lhs_true1"
  store i64 1, i64* %"&&_result5"
  br label %"&&_merge4"

"&&_false3":                                      ; preds = %"&&_lhs_true1", %"&&_merge"
  store i64 0, i64* %"&&_result5"
  br label %"&&_merge4"

"&&_merge4":                                      ; preds = %"&&_false3", %"&&_true2"
  %25 = load i64, i64* %"&&_result5"
  %26 = getelementptr %printf_t, %printf_t* %printf_args, i32 0, i32 2
  store i64 %25, i64* %26
  %27 = bitcast i64* %"||_result" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %27)
  %28 = add [4 x i8]* %"$foo", i64 0
  %29 = bitcast i32* %"struct Foo.m8" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %29)
  %probe_read_user9 = call i64 inttoptr (i64 112 to i64 (i32*, i32, [4 x i8]*)*)(i32* %"struct Foo.m8", i32 4, [4 x i8]* %28)
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
  %36 = add [4 x i8]* %"$foo", i64 0
  %37 = bitcast i32* %"struct Foo.m16" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %37)
  %probe_read_user17 = call i64 inttoptr (i64 112 to i64 (i32*, i32, [4 x i8]*)*)(i32* %"struct Foo.m16", i32 4, [4 x i8]* %36)
  %38 = load i32, i32* %"struct Foo.m16"
  %39 = sext i32 %38 to i64
  %40 = bitcast i32* %"struct Foo.m16" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %40)
  %rhs_true_cond18 = icmp ne i64 %39, 0
  br i1 %rhs_true_cond18, label %"||_true13", label %"||_false12"

"||_false12":                                     ; preds = %"||_lhs_false11"
  store i64 0, i64* %"||_result15"
  br label %"||_merge14"

"||_true13":                                      ; preds = %"||_lhs_false11", %"||_merge"
  store i64 1, i64* %"||_result15"
  br label %"||_merge14"

"||_merge14":                                     ; preds = %"||_true13", %"||_false12"
  %41 = load i64, i64* %"||_result15"
  %42 = getelementptr %printf_t, %printf_t* %printf_args, i32 0, i32 4
  store i64 %41, i64* %42
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %get_cpu_id = call i64 inttoptr (i64 8 to i64 ()*)()
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %printf_t*, i64)*)(i8* %0, i64 %pseudo, i64 %get_cpu_id, %printf_t* %printf_args, i64 40)
  %43 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %43)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i1) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.memcpy.p0i8.p64i8.i64(i8* nocapture writeonly, i8 addrspace(64)* nocapture readonly, i64, i1) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
