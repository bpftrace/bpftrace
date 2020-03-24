; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

%printf_t = type { i64, i32, i32, i32, i32 }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @BEGIN(i8*) local_unnamed_addr section "s_BEGIN_1" {
entry:
  %"struct Foo.m16" = alloca i32, align 4
  %"struct Foo.m8" = alloca i32, align 4
  %"struct Foo.m6" = alloca i32, align 4
  %"struct Foo.m" = alloca i32, align 4
  %printf_args = alloca %printf_t, align 8
  %"$foo" = alloca i32, align 4
  %tmpcast = bitcast i32* %"$foo" to [4 x i8]*
  %1 = bitcast i32* %"$foo" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  store i32 0, i32* %"$foo", align 4
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %2 = load i32, i32 addrspace(64)* null, align 536870912
  store i32 %2, i32* %"$foo", align 4
  %3 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %3)
  %4 = bitcast i32* %"struct Foo.m" to i8*
  %5 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.memset.p0i8.i64(i8* nonnull align 8 %5, i8 0, i64 24, i1 false)
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %4)
  %probe_read = call i64 inttoptr (i64 4 to i64 (i32*, i32, [4 x i8]*)*)(i32* nonnull %"struct Foo.m", i32 4, [4 x i8]* nonnull %tmpcast)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %4)
  %6 = getelementptr inbounds %printf_t, %printf_t* %printf_args, i64 0, i32 1
  store i1 false, i32* %6, align 8
  %7 = bitcast i32* %"struct Foo.m6" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %7)
  %probe_read7 = call i64 inttoptr (i64 4 to i64 (i32*, i32, [4 x i8]*)*)(i32* nonnull %"struct Foo.m6", i32 4, [4 x i8]* nonnull %tmpcast)
  %8 = load i32, i32* %"struct Foo.m6", align 4
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %7)
  %rhs_true_cond = icmp ne i32 %8, 0
  %9 = getelementptr inbounds %printf_t, %printf_t* %printf_args, i64 0, i32 2
  store i1 %rhs_true_cond, i32* %9, align 4
  %10 = bitcast i32* %"struct Foo.m8" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %10)
  %probe_read9 = call i64 inttoptr (i64 4 to i64 (i32*, i32, [4 x i8]*)*)(i32* nonnull %"struct Foo.m8", i32 4, [4 x i8]* nonnull %tmpcast)
  %11 = load i32, i32* %"struct Foo.m8", align 4
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %10)
  %lhs_true_cond10 = icmp ne i32 %11, 0
  %12 = getelementptr inbounds %printf_t, %printf_t* %printf_args, i64 0, i32 3
  store i1 %lhs_true_cond10, i32* %12, align 8
  %13 = bitcast i32* %"struct Foo.m16" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %13)
  %probe_read17 = call i64 inttoptr (i64 4 to i64 (i32*, i32, [4 x i8]*)*)(i32* nonnull %"struct Foo.m16", i32 4, [4 x i8]* nonnull %tmpcast)
  %14 = load i32, i32* %"struct Foo.m16", align 4
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %13)
  %rhs_true_cond18 = icmp ne i32 %14, 0
  %15 = getelementptr inbounds %printf_t, %printf_t* %printf_args, i64 0, i32 4
  store i1 %rhs_true_cond18, i32* %15, align 4
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %get_cpu_id = call i64 inttoptr (i64 8 to i64 ()*)()
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %printf_t*, i64)*)(i8* %0, i64 %pseudo, i64 %get_cpu_id, %printf_t* nonnull %printf_args, i64 24)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %3)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i1) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
