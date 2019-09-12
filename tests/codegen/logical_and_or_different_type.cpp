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
  %"$foo" = alloca i64, align 8
  %1 = bitcast i64* %"$foo" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %2 = bitcast i64* %"$foo" to i32*
  store i32 0, i32* %2, align 8
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %3 = load i32, i32 addrspace(64)* null, align 536870912
  store i32 %3, i32* %2, align 8
  %4 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %4)
  %5 = bitcast i32* %Foo.m to i8*
  %6 = getelementptr inbounds %printf_t, %printf_t* %printf_args, i64 0, i32 0
  store i64 0, i64* %6, align 8
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %5)
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i32* nonnull %Foo.m, i64 4, i8* nonnull %1)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %5)
  %7 = getelementptr inbounds %printf_t, %printf_t* %printf_args, i64 0, i32 1
  store i64 0, i64* %7, align 8
  %8 = bitcast i32* %Foo.m6 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %8)
  %probe_read7 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i32* nonnull %Foo.m6, i64 4, i8* nonnull %1)
  %9 = load i32, i32* %Foo.m6, align 4
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %8)
  %rhs_true_cond = icmp ne i32 %9, 0
  %"&&_result5.0" = zext i1 %rhs_true_cond to i64
  %10 = getelementptr inbounds %printf_t, %printf_t* %printf_args, i64 0, i32 2
  store i64 %"&&_result5.0", i64* %10, align 8
  %11 = bitcast i32* %Foo.m8 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %11)
  %probe_read9 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i32* nonnull %Foo.m8, i64 4, i8* nonnull %1)
  %12 = load i32, i32* %Foo.m8, align 4
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %11)
  %lhs_true_cond10 = icmp ne i32 %12, 0
  %"||_result.0" = zext i1 %lhs_true_cond10 to i64
  %13 = getelementptr inbounds %printf_t, %printf_t* %printf_args, i64 0, i32 3
  store i64 %"||_result.0", i64* %13, align 8
  %14 = bitcast i32* %Foo.m16 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %14)
  %probe_read17 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i32* nonnull %Foo.m16, i64 4, i8* nonnull %1)
  %15 = load i32, i32* %Foo.m16, align 4
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %14)
  %rhs_true_cond18 = icmp ne i32 %15, 0
  %"||_result15.0" = zext i1 %rhs_true_cond18 to i64
  %16 = getelementptr inbounds %printf_t, %printf_t* %printf_args, i64 0, i32 4
  store i64 %"||_result15.0", i64* %16, align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %get_cpu_id = call i64 inttoptr (i64 8 to i64 ()*)()
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %printf_t*, i64)*)(i8* %0, i64 %pseudo, i64 %get_cpu_id, %printf_t* nonnull %printf_args, i64 40)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %4)
  ret i64 0
}

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
  %"$foo" = alloca i64, align 8
  %1 = bitcast i64* %"$foo" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %2 = bitcast i64* %"$foo" to i32*
  store i32 0, i32* %2, align 8
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %3 = load i32, i32 addrspace(64)* null, align 536870912
  store i32 %3, i32* %2, align 8
  %4 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %4)
  %5 = bitcast i32* %Foo.m to i8*
  %6 = getelementptr inbounds %printf_t, %printf_t* %printf_args, i64 0, i32 0
  store i64 0, i64* %6, align 8
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %5)
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i32* nonnull %Foo.m, i64 4, i8* nonnull %1)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %5)
  %7 = getelementptr inbounds %printf_t, %printf_t* %printf_args, i64 0, i32 1
  store i64 0, i64* %7, align 8
  %8 = bitcast i32* %Foo.m6 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %8)
  %probe_read7 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i32* nonnull %Foo.m6, i64 4, i8* nonnull %1)
  %9 = load i32, i32* %Foo.m6, align 4
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %8)
  %rhs_true_cond = icmp ne i32 %9, 0
  %"&&_result5.0" = zext i1 %rhs_true_cond to i64
  %10 = getelementptr inbounds %printf_t, %printf_t* %printf_args, i64 0, i32 2
  store i64 %"&&_result5.0", i64* %10, align 8
  %11 = bitcast i32* %Foo.m8 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %11)
  %probe_read9 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i32* nonnull %Foo.m8, i64 4, i8* nonnull %1)
  %12 = load i32, i32* %Foo.m8, align 4
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %11)
  %lhs_true_cond10 = icmp ne i32 %12, 0
  %"||_result.0" = zext i1 %lhs_true_cond10 to i64
  %13 = getelementptr inbounds %printf_t, %printf_t* %printf_args, i64 0, i32 3
  store i64 %"||_result.0", i64* %13, align 8
  %14 = bitcast i32* %Foo.m16 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %14)
  %probe_read17 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i32* nonnull %Foo.m16, i64 4, i8* nonnull %1)
  %15 = load i32, i32* %Foo.m16, align 4
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %14)
  %rhs_true_cond18 = icmp ne i32 %15, 0
  %"||_result15.0" = zext i1 %rhs_true_cond18 to i64
  %16 = getelementptr inbounds %printf_t, %printf_t* %printf_args, i64 0, i32 4
  store i64 %"||_result15.0", i64* %16, align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %get_cpu_id = call i64 inttoptr (i64 8 to i64 ()*)()
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %printf_t*, i64)*)(i8* %0, i64 %pseudo, i64 %get_cpu_id, %printf_t* nonnull %printf_args, i64 40)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %4)
  ret i64 0
}

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

