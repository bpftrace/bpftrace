#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_cat)
{
  test("kprobe:f { cat(\"/proc/loadavg\"); }",

R"EXPECTED(%cat_t = type { i64 }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"kprobe:f"(i8*) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %cat_args = alloca %cat_t, align 8
  %1 = bitcast %cat_t* %cat_args to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %2 = getelementptr inbounds %cat_t, %cat_t* %cat_args, i64 0, i32 0
  store i64 20000, i64* %2, align 8
  %pseudo = tail call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %get_cpu_id = tail call i64 inttoptr (i64 8 to i64 ()*)()
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %cat_t*, i64)*)(i8* %0, i64 %pseudo, i64 %get_cpu_id, %cat_t* nonnull %cat_args, i64 8)
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
