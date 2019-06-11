#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_printf)
{
  test("struct Foo { char c; long l; } kprobe:f { $foo = (Foo*)0; printf(\"%c %lu\\n\", $foo->c, $foo->l) }",

R"EXPECTED(%printf_t = type { i64, i64, i64 }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"kprobe:f"(i8*) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %Foo.l = alloca i64, align 8
  %Foo.c = alloca i8, align 1
  %key = alloca i32, align 4
  %pseudo = tail call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  %1 = bitcast i32* %key to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  store i32 0, i32* %key, align 4
  %lookup_fmtstr_map = call %printf_t* inttoptr (i64 1 to %printf_t* (i8*, i8*)*)(i64 %pseudo, i32* nonnull %key)
  %fmtstrcond = icmp eq %printf_t* %lookup_fmtstr_map, null
  br i1 %fmtstrcond, label %fmtstrzero, label %fmtstrnotzero

fmtstrzero:                                       ; preds = %entry, %fmtstrnotzero
  ret i64 0

fmtstrnotzero:                                    ; preds = %entry
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(%printf_t* nonnull %lookup_fmtstr_map, i64 24, %printf_t* null)
  %2 = getelementptr %printf_t, %printf_t* %lookup_fmtstr_map, i64 0, i32 0
  store i64 0, i64* %2, align 8
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %Foo.c)
  %probe_read1 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i8* nonnull %Foo.c, i64 1, i64 0)
  %3 = load i8, i8* %Foo.c, align 1
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %Foo.c)
  %4 = getelementptr %printf_t, %printf_t* %lookup_fmtstr_map, i64 0, i32 1
  store i8 %3, i64* %4, align 1
  %5 = bitcast i64* %Foo.l to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %5)
  %probe_read2 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i64* nonnull %Foo.l, i64 8, i64 8)
  %6 = load i64, i64* %Foo.l, align 8
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %5)
  %7 = getelementptr %printf_t, %printf_t* %lookup_fmtstr_map, i64 0, i32 2
  store i64 %6, i64* %7, align 8
  %pseudo3 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %get_cpu_id = call i64 inttoptr (i64 8 to i64 ()*)()
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %printf_t*, i64)*)(i8* %0, i64 %pseudo3, i64 %get_cpu_id, %printf_t* nonnull %lookup_fmtstr_map, i64 24)
  %8 = bitcast %printf_t* %lookup_fmtstr_map to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %8)
  br label %fmtstrzero
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
