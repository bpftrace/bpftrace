#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, struct_semicolon)
{
  auto expected = R"EXPECTED(%printf_t = type { i64, i64 }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"kprobe:f"(i8*) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %key = alloca i32, align 4
  %pseudo = tail call i64 @llvm.bpf.pseudo(i64 1, i64 3)
  %1 = bitcast i32* %key to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  store i32 0, i32* %key, align 4
  %lookup_fmtstr_map = call %printf_t* inttoptr (i64 1 to %printf_t* (i8*, i8*)*)(i64 %pseudo, i32* nonnull %key)
  %fmtstrcond = icmp eq %printf_t* %lookup_fmtstr_map, null
  br i1 %fmtstrcond, label %fmtstrzero, label %fmtstrnotzero

fmtstrzero:                                       ; preds = %entry, %fmtstrnotzero
  ret i64 0

fmtstrnotzero:                                    ; preds = %entry
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(%printf_t* nonnull %lookup_fmtstr_map, i64 16, %printf_t* null)
  %2 = getelementptr %printf_t, %printf_t* %lookup_fmtstr_map, i64 0, i32 0
  store i64 0, i64* %2, align 8
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %get_stackid = call i64 inttoptr (i64 27 to i64 (i8*, i8*, i64)*)(i8* %0, i64 %pseudo1, i64 256)
  %get_pid_tgid = call i64 inttoptr (i64 14 to i64 ()*)()
  %3 = shl i64 %get_pid_tgid, 32
  %4 = or i64 %3, %get_stackid
  %5 = getelementptr %printf_t, %printf_t* %lookup_fmtstr_map, i64 0, i32 1
  store i64 %4, i64* %5, align 8
  %pseudo2 = call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  %get_cpu_id = call i64 inttoptr (i64 8 to i64 ()*)()
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %printf_t*, i64)*)(i8* %0, i64 %pseudo2, i64 %get_cpu_id, %printf_t* nonnull %lookup_fmtstr_map, i64 16)
  %6 = bitcast %printf_t* %lookup_fmtstr_map to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %6)
  br label %fmtstrzero
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
)EXPECTED";

  test("struct Foo { int x, y; char *str; };"
       "k:f"
       "{"
       "  printf(\"%s\\n\", ustack);"
       "}",
       expected);

  test("struct Foo { int x, y; char *str; }"
       "k:f"
       "{"
       "  printf(\"%s\\n\", ustack);"
       "}",
       expected);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
