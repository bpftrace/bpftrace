#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, unroll)
{
  test("kprobe:f { $i = 0; unroll(5) { printf(\"i: %d\\n\", $i); $i = $i + 1; } }",

#if LLVM_VERSION_MAJOR > 6
R"EXPECTED(%printf_t = type { i64, i64 }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"kprobe:f"(i8*) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %printf_args = alloca %printf_t, align 8
  %1 = bitcast %printf_t* %printf_args to i8*
  %2 = getelementptr inbounds %printf_t, %printf_t* %printf_args, i64 0, i32 1
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %3 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.memset.p0i8.i64(i8* nonnull align 8 %3, i8 0, i64 16, i1 false)
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %get_cpu_id = call i64 inttoptr (i64 8 to i64 ()*)()
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i8*, i64, i8*, i64)*)(i8* %0, i64 %pseudo, i64 %get_cpu_id, %printf_t* nonnull %printf_args, i64 16)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %4 = getelementptr inbounds %printf_t, %printf_t* %printf_args, i64 0, i32 0
  store i64 0, i64* %4, align 8
  store i64 1, i64* %2, align 8
  %pseudo.1 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %get_cpu_id.1 = call i64 inttoptr (i64 8 to i64 ()*)()
  %perf_event_output.1 = call i64 inttoptr (i64 25 to i64 (i8*, i8*, i64, i8*, i64)*)(i8* %0, i64 %pseudo.1, i64 %get_cpu_id.1, %printf_t* nonnull %printf_args, i64 16)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %5 = getelementptr inbounds %printf_t, %printf_t* %printf_args, i64 0, i32 0
  store i64 0, i64* %5, align 8
  store i64 2, i64* %2, align 8
  %pseudo.2 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %get_cpu_id.2 = call i64 inttoptr (i64 8 to i64 ()*)()
  %perf_event_output.2 = call i64 inttoptr (i64 25 to i64 (i8*, i8*, i64, i8*, i64)*)(i8* %0, i64 %pseudo.2, i64 %get_cpu_id.2, %printf_t* nonnull %printf_args, i64 16)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %6 = getelementptr inbounds %printf_t, %printf_t* %printf_args, i64 0, i32 0
  store i64 0, i64* %6, align 8
  store i64 3, i64* %2, align 8
  %pseudo.3 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %get_cpu_id.3 = call i64 inttoptr (i64 8 to i64 ()*)()
  %perf_event_output.3 = call i64 inttoptr (i64 25 to i64 (i8*, i8*, i64, i8*, i64)*)(i8* %0, i64 %pseudo.3, i64 %get_cpu_id.3, %printf_t* nonnull %printf_args, i64 16)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %7 = getelementptr inbounds %printf_t, %printf_t* %printf_args, i64 0, i32 0
  store i64 0, i64* %7, align 8
  store i64 4, i64* %2, align 8
  %pseudo.4 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %get_cpu_id.4 = call i64 inttoptr (i64 8 to i64 ()*)()
  %perf_event_output.4 = call i64 inttoptr (i64 25 to i64 (i8*, i8*, i64, i8*, i64)*)(i8* %0, i64 %pseudo.4, i64 %get_cpu_id.4, %printf_t* nonnull %printf_args, i64 16)
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
#else
R"EXPECTED(%printf_t = type { i64, i64 }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"kprobe:f"(i8*) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %printf_args = alloca %printf_t, align 8
  %1 = bitcast %printf_t* %printf_args to i8*
  %2 = getelementptr inbounds %printf_t, %printf_t* %printf_args, i64 0, i32 1
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %3 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.memset.p0i8.i64(i8* nonnull %3, i8 0, i64 16, i32 8, i1 false)
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %get_cpu_id = call i64 inttoptr (i64 8 to i64 ()*)()
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i8*, i64, i8*, i64)*)(i8* %0, i64 %pseudo, i64 %get_cpu_id, %printf_t* nonnull %printf_args, i64 16)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %4 = getelementptr inbounds %printf_t, %printf_t* %printf_args, i64 0, i32 0
  store i64 0, i64* %4, align 8
  store i64 1, i64* %2, align 8
  %pseudo.1 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %get_cpu_id.1 = call i64 inttoptr (i64 8 to i64 ()*)()
  %perf_event_output.1 = call i64 inttoptr (i64 25 to i64 (i8*, i8*, i64, i8*, i64)*)(i8* %0, i64 %pseudo.1, i64 %get_cpu_id.1, %printf_t* nonnull %printf_args, i64 16)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %5 = getelementptr inbounds %printf_t, %printf_t* %printf_args, i64 0, i32 0
  store i64 0, i64* %5, align 8
  store i64 2, i64* %2, align 8
  %pseudo.2 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %get_cpu_id.2 = call i64 inttoptr (i64 8 to i64 ()*)()
  %perf_event_output.2 = call i64 inttoptr (i64 25 to i64 (i8*, i8*, i64, i8*, i64)*)(i8* %0, i64 %pseudo.2, i64 %get_cpu_id.2, %printf_t* nonnull %printf_args, i64 16)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %6 = getelementptr inbounds %printf_t, %printf_t* %printf_args, i64 0, i32 0
  store i64 0, i64* %6, align 8
  store i64 3, i64* %2, align 8
  %pseudo.3 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %get_cpu_id.3 = call i64 inttoptr (i64 8 to i64 ()*)()
  %perf_event_output.3 = call i64 inttoptr (i64 25 to i64 (i8*, i8*, i64, i8*, i64)*)(i8* %0, i64 %pseudo.3, i64 %get_cpu_id.3, %printf_t* nonnull %printf_args, i64 16)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %7 = getelementptr inbounds %printf_t, %printf_t* %printf_args, i64 0, i32 0
  store i64 0, i64* %7, align 8
  store i64 4, i64* %2, align 8
  %pseudo.4 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %get_cpu_id.4 = call i64 inttoptr (i64 8 to i64 ()*)()
  %perf_event_output.4 = call i64 inttoptr (i64 25 to i64 (i8*, i8*, i64, i8*, i64)*)(i8* %0, i64 %pseudo.4, i64 %get_cpu_id.4, %printf_t* nonnull %printf_args, i64 16)
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
#endif
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
