#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, if_nested_printf)
{
  test("kprobe:f { if (pid > 10000) { if (pid % 2 == 0) { printf(\"hi\\n\");} } }",

R"EXPECTED(%printf_t = type { i64 }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"kprobe:f"(i8*) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %key = alloca i32, align 4
  %get_pid_tgid = tail call i64 inttoptr (i64 14 to i64 ()*)()
  %1 = icmp ugt i64 %get_pid_tgid, 42953967927295
  br i1 %1, label %if_stmt, label %else_stmt

if_stmt:                                          ; preds = %entry
  %get_pid_tgid3 = tail call i64 inttoptr (i64 14 to i64 ()*)()
  %.lobit = and i64 %get_pid_tgid3, 4294967296
  %true_cond4 = icmp eq i64 %.lobit, 0
  br i1 %true_cond4, label %if_stmt1, label %else_stmt

else_stmt:                                        ; preds = %fmtstrnotzero, %if_stmt1, %if_stmt, %entry
  ret i64 0

if_stmt1:                                         ; preds = %if_stmt
  %pseudo = tail call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  %2 = bitcast i32* %key to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %2)
  store i32 0, i32* %key, align 4
  %lookup_fmtstr_map = call %printf_t* inttoptr (i64 1 to %printf_t* (i8*, i8*)*)(i64 %pseudo, i32* nonnull %key)
  %fmtstrcond = icmp eq %printf_t* %lookup_fmtstr_map, null
  br i1 %fmtstrcond, label %else_stmt, label %fmtstrnotzero

fmtstrnotzero:                                    ; preds = %if_stmt1
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(%printf_t* nonnull %lookup_fmtstr_map, i64 8, %printf_t* null)
  %3 = getelementptr %printf_t, %printf_t* %lookup_fmtstr_map, i64 0, i32 0
  store i64 0, i64* %3, align 8
  %pseudo5 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %get_cpu_id = call i64 inttoptr (i64 8 to i64 ()*)()
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %printf_t*, i64)*)(i8* %0, i64 %pseudo5, i64 %get_cpu_id, %printf_t* nonnull %lookup_fmtstr_map, i64 8)
  %4 = bitcast %printf_t* %lookup_fmtstr_map to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %4)
  br label %else_stmt
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
