#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, if_else_printf)
{
  test("kprobe:f { if (pid > 10) { printf(\"hi\\n\"); } else {printf(\"hello\\n\")} }",

R"EXPECTED(%printf_t = type { i64 }
%printf_t.0 = type { i64 }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"kprobe:f"(i8*) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %key3 = alloca i32, align 4
  %key = alloca i32, align 4
  %get_pid_tgid = tail call i64 inttoptr (i64 14 to i64 ()*)()
  %1 = icmp ugt i64 %get_pid_tgid, 47244640255
  %pseudo = tail call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  br i1 %1, label %if_stmt, label %else_stmt

if_stmt:                                          ; preds = %entry
  %2 = bitcast i32* %key to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %2)
  store i32 0, i32* %key, align 4
  %lookup_fmtstr_map = call %printf_t* inttoptr (i64 1 to %printf_t* (i8*, i8*)*)(i64 %pseudo, i32* nonnull %key)
  %fmtstrcond = icmp eq %printf_t* %lookup_fmtstr_map, null
  br i1 %fmtstrcond, label %done, label %fmtstrnotzero

else_stmt:                                        ; preds = %entry
  %3 = bitcast i32* %key3 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %3)
  store i32 0, i32* %key3, align 4
  %lookup_fmtstr_map4 = call %printf_t.0* inttoptr (i64 1 to %printf_t.0* (i8*, i8*)*)(i64 %pseudo, i32* nonnull %key3)
  %fmtstrcond7 = icmp eq %printf_t.0* %lookup_fmtstr_map4, null
  br i1 %fmtstrcond7, label %done, label %fmtstrnotzero6

fmtstrnotzero:                                    ; preds = %if_stmt
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(%printf_t* nonnull %lookup_fmtstr_map, i64 8, %printf_t* null)
  %4 = getelementptr %printf_t, %printf_t* %lookup_fmtstr_map, i64 0, i32 0
  store i64 0, i64* %4, align 8
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %get_cpu_id = call i64 inttoptr (i64 8 to i64 ()*)()
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %printf_t*, i64)*)(i8* %0, i64 %pseudo1, i64 %get_cpu_id, %printf_t* nonnull %lookup_fmtstr_map, i64 8)
  %5 = bitcast %printf_t* %lookup_fmtstr_map to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %5)
  br label %done

done:                                             ; preds = %fmtstrnotzero6, %else_stmt, %fmtstrnotzero, %if_stmt
  ret i64 0

fmtstrnotzero6:                                   ; preds = %else_stmt
  %probe_read8 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(%printf_t.0* nonnull %lookup_fmtstr_map4, i64 8, %printf_t.0* null)
  %6 = getelementptr %printf_t.0, %printf_t.0* %lookup_fmtstr_map4, i64 0, i32 0
  store i64 1, i64* %6, align 8
  %pseudo9 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %get_cpu_id10 = call i64 inttoptr (i64 8 to i64 ()*)()
  %perf_event_output11 = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %printf_t.0*, i64)*)(i8* %0, i64 %pseudo9, i64 %get_cpu_id10, %printf_t.0* nonnull %lookup_fmtstr_map4, i64 8)
  %7 = bitcast %printf_t.0* %lookup_fmtstr_map4 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %7)
  br label %done
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
