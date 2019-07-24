#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, logical_and_or_different_type)
{
  test("struct Foo { int m; } BEGIN { $foo = (struct Foo)0; printf(\"%d %d %d %d\", $foo.m && 0, 1 && $foo.m, $foo.m || 0, 0 || $foo.m); }",

#if LLVM_VERSION_MAJOR > 6
R"EXPECTED(%printf_t = type { i64, i64, i64, i64, i64 }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @BEGIN(i8*) local_unnamed_addr section "s_BEGIN_1" {
entry:
  %Foo.m16 = alloca i32, align 4
  %Foo.m8 = alloca i32, align 4
  %Foo.m6 = alloca i32, align 4
  %Foo.m = alloca i32, align 4
  %printf_args = alloca %printf_t, align 8
  %"$foo" = alloca i32, align 4
  %tmpcast = bitcast i32* %"$foo" to [4 x i8]*
  %1 = bitcast i32* %"$foo" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  call void @llvm.memset.p0i8.i64(i8* nonnull align 4 %1, i64 0, i64 4, i1 false)
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %2 = load i32, i32 addrspace(64)* null, align 536870912
  store i32 %2, i32* %"$foo", align 4
  %3 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %3)
  %4 = bitcast i32* %Foo.m to i8*
  %5 = getelementptr inbounds %printf_t, %printf_t* %printf_args, i64 0, i32 0
  store i64 0, i64* %5, align 8
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %4)
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i32* nonnull %Foo.m, i64 4, [4 x i8]* nonnull %tmpcast)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %4)
  %6 = getelementptr inbounds %printf_t, %printf_t* %printf_args, i64 0, i32 1
  store i64 0, i64* %6, align 8
  %7 = bitcast i32* %Foo.m6 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %7)
  %probe_read7 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i32* nonnull %Foo.m6, i64 4, [4 x i8]* nonnull %tmpcast)
  %8 = load i32, i32* %Foo.m6, align 4
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %7)
  %rhs_true_cond = icmp ne i32 %8, 0
  %"&&_result5.0" = zext i1 %rhs_true_cond to i64
  %9 = getelementptr inbounds %printf_t, %printf_t* %printf_args, i64 0, i32 2
  store i64 %"&&_result5.0", i64* %9, align 8
  %10 = bitcast i32* %Foo.m8 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %10)
  %probe_read9 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i32* nonnull %Foo.m8, i64 4, [4 x i8]* nonnull %tmpcast)
  %11 = load i32, i32* %Foo.m8, align 4
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %10)
  %lhs_true_cond10 = icmp ne i32 %11, 0
  %"||_result.0" = zext i1 %lhs_true_cond10 to i64
  %12 = getelementptr inbounds %printf_t, %printf_t* %printf_args, i64 0, i32 3
  store i64 %"||_result.0", i64* %12, align 8
  %13 = bitcast i32* %Foo.m16 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %13)
  %probe_read17 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i32* nonnull %Foo.m16, i64 4, [4 x i8]* nonnull %tmpcast)
  %14 = load i32, i32* %Foo.m16, align 4
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %13)
  %rhs_true_cond18 = icmp ne i32 %14, 0
  %"||_result15.0" = zext i1 %rhs_true_cond18 to i64
  %15 = getelementptr inbounds %printf_t, %printf_t* %printf_args, i64 0, i32 4
  store i64 %"||_result15.0", i64* %15, align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %get_cpu_id = call i64 inttoptr (i64 8 to i64 ()*)()
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %printf_t*, i64)*)(i8* %0, i64 %pseudo, i64 %get_cpu_id, %printf_t* nonnull %printf_args, i64 40)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %3)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i1) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
)EXPECTED");
#else
R"EXPECTED(%printf_t = type { i64, i64, i64, i64, i64 }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @BEGIN(i8*) local_unnamed_addr section "s_BEGIN_1" {
entry:
  %Foo.m16 = alloca i32, align 4
  %Foo.m8 = alloca i32, align 4
  %Foo.m6 = alloca i32, align 4
  %Foo.m = alloca i32, align 4
  %printf_args = alloca %printf_t, align 8
  %"$foo" = alloca i32, align 4
  %tmpcast = bitcast i32* %"$foo" to [4 x i8]*
  %1 = bitcast i32* %"$foo" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  call void @llvm.memset.p0i8.i64(i8* nonnull %1, i64 0, i64 4, i32 4, i1 false)
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %2 = load i32, i32 addrspace(64)* null, align 536870912
  store i32 %2, i32* %"$foo", align 4
  %3 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %3)
  %4 = bitcast i32* %Foo.m to i8*
  %5 = getelementptr inbounds %printf_t, %printf_t* %printf_args, i64 0, i32 0
  store i64 0, i64* %5, align 8
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %4)
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i32* nonnull %Foo.m, i64 4, [4 x i8]* nonnull %tmpcast)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %4)
  %6 = getelementptr inbounds %printf_t, %printf_t* %printf_args, i64 0, i32 1
  store i64 0, i64* %6, align 8
  %7 = bitcast i32* %Foo.m6 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %7)
  %probe_read7 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i32* nonnull %Foo.m6, i64 4, [4 x i8]* nonnull %tmpcast)
  %8 = load i32, i32* %Foo.m6, align 4
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %7)
  %rhs_true_cond = icmp ne i32 %8, 0
  %"&&_result5.0" = zext i1 %rhs_true_cond to i64
  %9 = getelementptr inbounds %printf_t, %printf_t* %printf_args, i64 0, i32 2
  store i64 %"&&_result5.0", i64* %9, align 8
  %10 = bitcast i32* %Foo.m8 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %10)
  %probe_read9 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i32* nonnull %Foo.m8, i64 4, [4 x i8]* nonnull %tmpcast)
  %11 = load i32, i32* %Foo.m8, align 4
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %10)
  %lhs_true_cond10 = icmp ne i32 %11, 0
  %"||_result.0" = zext i1 %lhs_true_cond10 to i64
  %12 = getelementptr inbounds %printf_t, %printf_t* %printf_args, i64 0, i32 3
  store i64 %"||_result.0", i64* %12, align 8
  %13 = bitcast i32* %Foo.m16 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %13)
  %probe_read17 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i32* nonnull %Foo.m16, i64 4, [4 x i8]* nonnull %tmpcast)
  %14 = load i32, i32* %Foo.m16, align 4
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %13)
  %rhs_true_cond18 = icmp ne i32 %14, 0
  %"||_result15.0" = zext i1 %rhs_true_cond18 to i64
  %15 = getelementptr inbounds %printf_t, %printf_t* %printf_args, i64 0, i32 4
  store i64 %"||_result15.0", i64* %15, align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %get_cpu_id = call i64 inttoptr (i64 8 to i64 ()*)()
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %printf_t*, i64)*)(i8* %0, i64 %pseudo, i64 %get_cpu_id, %printf_t* nonnull %printf_args, i64 40)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %3)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i32, i1) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
)EXPECTED");
#endif
}

} // namespace codegen
} // namespace test
} // namespace bpftrace

