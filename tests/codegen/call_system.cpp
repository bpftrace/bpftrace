#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_system)
{
  test(" kprobe:f { system(\"echo %d\", 100) }",

R"EXPECTED(%system_t = type { i64, i64 }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"kprobe:f"(i8*) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %system_args = alloca %system_t, align 8
  %1 = bitcast %system_t* %system_args to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  store i64 10000, %system_t* %system_args, align 8
  %2 = getelementptr inbounds %system_t, %system_t* %system_args, i64 0, i32 1
  store i64 100, i64* %2, align 8
  %pseudo = tail call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %get_cpu_id = tail call i64 inttoptr (i64 8 to i64 ()*)()
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i8*, i64, i8*, i64)*)(i8* %0, i64 %pseudo, i64 %get_cpu_id, %system_t* nonnull %system_args, i64 16)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
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
