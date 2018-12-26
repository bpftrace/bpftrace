#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_printf)
{
  test("struct Foo { char c; long l; } kprobe:f { $foo = (Foo*)0; printf(\"%c %lu\\n\", $foo->c, $foo->l) }",

#if LLVM_VERSION_MAJOR < 7
R"EXPECTED(%printf_t = type { i64, i64, i64 }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"kprobe:f"(i8*) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %Foo.l = alloca i64, align 8
  %Foo.c = alloca i8, align 1
  %printf_args = alloca %printf_t, align 8
  %1 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %2 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.memset.p0i8.i64(i8* nonnull %2, i8 0, i64 16, i32 8, i1 false)
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %Foo.c)
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %Foo.c, i64 1, i64 0)
  %3 = load i8, i8* %Foo.c, align 1
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %Foo.c)
  %4 = getelementptr inbounds %printf_t, %printf_t* %printf_args, i64 0, i32 1
  store i8 %3, i64* %4, align 8
  %5 = bitcast i64* %Foo.l to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %5)
  %probe_read1 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i64* nonnull %Foo.l, i64 8, i64 8)
  %6 = load i64, i64* %Foo.l, align 8
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %5)
  %7 = getelementptr inbounds %printf_t, %printf_t* %printf_args, i64 0, i32 2
  store i64 %6, i64* %7, align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %get_cpu_id = call i64 inttoptr (i64 8 to i64 ()*)()
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i8*, i64, i8*, i64)*)(i8* %0, i64 %pseudo, i64 %get_cpu_id, %printf_t* nonnull %printf_args, i64 24)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i32, i1) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
)EXPECTED");
#else
R"EXPECTED(%printf_t = type { i64, i64, i64 }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"kprobe:f"(i8*) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %Foo.l = alloca i64, align 8
  %Foo.c = alloca i8, align 1
  %printf_args = alloca %printf_t, align 8
  %1 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %2 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.memset.p0i8.i64(i8* nonnull align 8 %2, i8 0, i64 16, i1 false)
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %Foo.c)
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %Foo.c, i64 1, i64 0)
  %3 = load i8, i8* %Foo.c, align 1
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %Foo.c)
  %4 = getelementptr inbounds %printf_t, %printf_t* %printf_args, i64 0, i32 1
  store i8 %3, i64* %4, align 8
  %5 = bitcast i64* %Foo.l to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %5)
  %probe_read1 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i64* nonnull %Foo.l, i64 8, i64 8)
  %6 = load i64, i64* %Foo.l, align 8
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %5)
  %7 = getelementptr inbounds %printf_t, %printf_t* %printf_args, i64 0, i32 2
  store i64 %6, i64* %7, align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %get_cpu_id = call i64 inttoptr (i64 8 to i64 ()*)()
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i8*, i64, i8*, i64)*)(i8* %0, i64 %pseudo, i64 %get_cpu_id, %printf_t* nonnull %printf_args, i64 24)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i1) #1

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
