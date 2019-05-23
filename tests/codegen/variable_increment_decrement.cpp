#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, variable_increment_decrement)
{
  test("BEGIN { $x = 10; printf(\"%d\", $x++); printf(\"%d\", ++$x); printf(\"%d\", $x--); printf(\"%d\", --$x); }",

R"EXPECTED(%printf_t.2 = type { i64, i64 }
%printf_t.1 = type { i64, i64 }
%printf_t.0 = type { i64, i64 }
%printf_t = type { i64, i64 }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @BEGIN(i8*) local_unnamed_addr section "s_BEGIN_1" {
entry:
  %printf_args9 = alloca %printf_t.2, align 8
  %printf_args5 = alloca %printf_t.1, align 8
  %printf_args1 = alloca %printf_t.0, align 8
  %printf_args = alloca %printf_t, align 8
  %1 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %2 = getelementptr inbounds %printf_t, %printf_t* %printf_args, i64 0, i32 1
  %3 = getelementptr inbounds %printf_t, %printf_t* %printf_args, i64 0, i32 0
  store i64 0, i64* %3, align 8
  store i64 10, i64* %2, align 8
  %pseudo = tail call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %get_cpu_id = tail call i64 inttoptr (i64 8 to i64 ()*)()
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i8*, i64, i8*, i64)*)(i8* %0, i64 %pseudo, i64 %get_cpu_id, %printf_t* nonnull %printf_args, i64 16)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  %4 = bitcast %printf_t.0* %printf_args1 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %4)
  %5 = getelementptr inbounds %printf_t.0, %printf_t.0* %printf_args1, i64 0, i32 0
  store i64 1, i64* %5, align 8
  %6 = getelementptr inbounds %printf_t.0, %printf_t.0* %printf_args1, i64 0, i32 1
  store i64 12, i64* %6, align 8
  %pseudo2 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %get_cpu_id3 = call i64 inttoptr (i64 8 to i64 ()*)()
  %perf_event_output4 = call i64 inttoptr (i64 25 to i64 (i8*, i8*, i64, i8*, i64)*)(i8* %0, i64 %pseudo2, i64 %get_cpu_id3, %printf_t.0* nonnull %printf_args1, i64 16)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %4)
  %7 = bitcast %printf_t.1* %printf_args5 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %7)
  %8 = getelementptr inbounds %printf_t.1, %printf_t.1* %printf_args5, i64 0, i32 0
  store i64 2, i64* %8, align 8
  %9 = getelementptr inbounds %printf_t.1, %printf_t.1* %printf_args5, i64 0, i32 1
  store i64 12, i64* %9, align 8
  %pseudo6 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %get_cpu_id7 = call i64 inttoptr (i64 8 to i64 ()*)()
  %perf_event_output8 = call i64 inttoptr (i64 25 to i64 (i8*, i8*, i64, i8*, i64)*)(i8* %0, i64 %pseudo6, i64 %get_cpu_id7, %printf_t.1* nonnull %printf_args5, i64 16)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %7)
  %10 = bitcast %printf_t.2* %printf_args9 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %10)
  %11 = getelementptr inbounds %printf_t.2, %printf_t.2* %printf_args9, i64 0, i32 0
  store i64 3, i64* %11, align 8
  %12 = getelementptr inbounds %printf_t.2, %printf_t.2* %printf_args9, i64 0, i32 1
  store i64 10, i64* %12, align 8
  %pseudo10 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %get_cpu_id11 = call i64 inttoptr (i64 8 to i64 ()*)()
  %perf_event_output12 = call i64 inttoptr (i64 25 to i64 (i8*, i8*, i64, i8*, i64)*)(i8* %0, i64 %pseudo10, i64 %get_cpu_id11, %printf_t.2* nonnull %printf_args9, i64 16)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %10)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
)EXPECTED");
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
