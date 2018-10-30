#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, if_else_printf)
{
  test("kprobe:f { if (pid > 10) { printf(\"hi\\n\"); } else {printf(\"hello\\n\")} }",

R"EXPECTED(%printf_t.0 = type { i64 }
%printf_t = type { i64 }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"kprobe:f"(i8*) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %printf_args1 = alloca %printf_t.0, align 8
  %printf_args = alloca %printf_t, align 8
  %get_pid_tgid = tail call i64 inttoptr (i64 14 to i64 ()*)()
  %1 = icmp ugt i64 %get_pid_tgid, 47244640255
  br i1 %1, label %if_stmt, label %else_stmt

if_stmt:                                          ; preds = %entry
  %2 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %2)
  store i64 0, %printf_t* %printf_args, align 8
  %pseudo = tail call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %get_cpu_id = tail call i64 inttoptr (i64 8 to i64 ()*)()
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i8*, i64, i8*, i64)*)(i8* %0, i64 %pseudo, i64 %get_cpu_id, %printf_t* nonnull %printf_args, i64 8)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %2)
  br label %done

else_stmt:                                        ; preds = %entry
  %3 = bitcast %printf_t.0* %printf_args1 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %3)
  store i64 1, %printf_t.0* %printf_args1, align 8
  %pseudo2 = tail call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %get_cpu_id3 = tail call i64 inttoptr (i64 8 to i64 ()*)()
  %perf_event_output4 = call i64 inttoptr (i64 25 to i64 (i8*, i8*, i64, i8*, i64)*)(i8* %0, i64 %pseudo2, i64 %get_cpu_id3, %printf_t.0* nonnull %printf_args1, i64 8)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %3)
  br label %done

done:                                             ; preds = %else_stmt, %if_stmt
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
