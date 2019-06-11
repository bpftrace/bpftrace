#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, variable_increment_decrement)
{
  test("BEGIN { $x = 10; printf(\"%d\", $x++); printf(\"%d\", ++$x); printf(\"%d\", $x--); printf(\"%d\", --$x); }",

R"EXPECTED(%printf_t = type { i64, i64 }
%printf_t.0 = type { i64, i64 }
%printf_t.1 = type { i64, i64 }
%printf_t.2 = type { i64, i64 }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @BEGIN(i8*) local_unnamed_addr section "s_BEGIN_1" {
entry:
  %key23 = alloca i32, align 4
  %key13 = alloca i32, align 4
  %key3 = alloca i32, align 4
  %key = alloca i32, align 4
  %pseudo = tail call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  %1 = bitcast i32* %key to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  store i32 0, i32* %key, align 4
  %lookup_fmtstr_map = call %printf_t* inttoptr (i64 1 to %printf_t* (i8*, i8*)*)(i64 %pseudo, i32* nonnull %key)
  %fmtstrcond = icmp eq %printf_t* %lookup_fmtstr_map, null
  br i1 %fmtstrcond, label %fmtstrzero, label %fmtstrnotzero

fmtstrzero:                                       ; preds = %entry, %fmtstrnotzero
  %"$x.0" = phi i64 [ 11, %fmtstrnotzero ], [ 10, %entry ]
  %pseudo2 = call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  %2 = bitcast i32* %key3 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %2)
  store i32 0, i32* %key3, align 4
  %lookup_fmtstr_map4 = call %printf_t.0* inttoptr (i64 1 to %printf_t.0* (i8*, i8*)*)(i64 %pseudo2, i32* nonnull %key3)
  %fmtstrcond7 = icmp eq %printf_t.0* %lookup_fmtstr_map4, null
  br i1 %fmtstrcond7, label %fmtstrzero5, label %fmtstrnotzero6

fmtstrnotzero:                                    ; preds = %entry
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(%printf_t* nonnull %lookup_fmtstr_map, i64 16, %printf_t* null)
  %3 = getelementptr %printf_t, %printf_t* %lookup_fmtstr_map, i64 0, i32 0
  store i64 0, i64* %3, align 8
  %4 = getelementptr %printf_t, %printf_t* %lookup_fmtstr_map, i64 0, i32 1
  store i64 10, i64* %4, align 8
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %get_cpu_id = call i64 inttoptr (i64 8 to i64 ()*)()
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %printf_t*, i64)*)(i8* %0, i64 %pseudo1, i64 %get_cpu_id, %printf_t* nonnull %lookup_fmtstr_map, i64 16)
  %5 = bitcast %printf_t* %lookup_fmtstr_map to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %5)
  br label %fmtstrzero

fmtstrzero5:                                      ; preds = %fmtstrzero, %fmtstrnotzero6
  %"$x.1" = phi i64 [ %8, %fmtstrnotzero6 ], [ %"$x.0", %fmtstrzero ]
  %pseudo12 = call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  %6 = bitcast i32* %key13 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %6)
  store i32 0, i32* %key13, align 4
  %lookup_fmtstr_map14 = call %printf_t.1* inttoptr (i64 1 to %printf_t.1* (i8*, i8*)*)(i64 %pseudo12, i32* nonnull %key13)
  %fmtstrcond17 = icmp eq %printf_t.1* %lookup_fmtstr_map14, null
  br i1 %fmtstrcond17, label %fmtstrzero15, label %fmtstrnotzero16

fmtstrnotzero6:                                   ; preds = %fmtstrzero
  %probe_read8 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(%printf_t.0* nonnull %lookup_fmtstr_map4, i64 16, %printf_t.0* null)
  %7 = getelementptr %printf_t.0, %printf_t.0* %lookup_fmtstr_map4, i64 0, i32 0
  store i64 1, i64* %7, align 8
  %8 = add nuw nsw i64 %"$x.0", 1
  %9 = getelementptr %printf_t.0, %printf_t.0* %lookup_fmtstr_map4, i64 0, i32 1
  store i64 %8, i64* %9, align 8
  %pseudo9 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %get_cpu_id10 = call i64 inttoptr (i64 8 to i64 ()*)()
  %perf_event_output11 = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %printf_t.0*, i64)*)(i8* %0, i64 %pseudo9, i64 %get_cpu_id10, %printf_t.0* nonnull %lookup_fmtstr_map4, i64 16)
  %10 = bitcast %printf_t.0* %lookup_fmtstr_map4 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %10)
  br label %fmtstrzero5

fmtstrzero15:                                     ; preds = %fmtstrzero5, %fmtstrnotzero16
  %"$x.2" = phi i64 [ %13, %fmtstrnotzero16 ], [ %"$x.1", %fmtstrzero5 ]
  %pseudo22 = call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  %11 = bitcast i32* %key23 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %11)
  store i32 0, i32* %key23, align 4
  %lookup_fmtstr_map24 = call %printf_t.2* inttoptr (i64 1 to %printf_t.2* (i8*, i8*)*)(i64 %pseudo22, i32* nonnull %key23)
  %fmtstrcond27 = icmp eq %printf_t.2* %lookup_fmtstr_map24, null
  br i1 %fmtstrcond27, label %fmtstrzero25, label %fmtstrnotzero26

fmtstrnotzero16:                                  ; preds = %fmtstrzero5
  %probe_read18 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(%printf_t.1* nonnull %lookup_fmtstr_map14, i64 16, %printf_t.1* null)
  %12 = getelementptr %printf_t.1, %printf_t.1* %lookup_fmtstr_map14, i64 0, i32 0
  store i64 2, i64* %12, align 8
  %13 = add nsw i64 %"$x.1", -1
  %14 = getelementptr %printf_t.1, %printf_t.1* %lookup_fmtstr_map14, i64 0, i32 1
  store i64 %"$x.1", i64* %14, align 8
  %pseudo19 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %get_cpu_id20 = call i64 inttoptr (i64 8 to i64 ()*)()
  %perf_event_output21 = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %printf_t.1*, i64)*)(i8* %0, i64 %pseudo19, i64 %get_cpu_id20, %printf_t.1* nonnull %lookup_fmtstr_map14, i64 16)
  %15 = bitcast %printf_t.1* %lookup_fmtstr_map14 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %15)
  br label %fmtstrzero15

fmtstrzero25:                                     ; preds = %fmtstrzero15, %fmtstrnotzero26
  ret i64 0

fmtstrnotzero26:                                  ; preds = %fmtstrzero15
  %probe_read28 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(%printf_t.2* nonnull %lookup_fmtstr_map24, i64 16, %printf_t.2* null)
  %16 = getelementptr %printf_t.2, %printf_t.2* %lookup_fmtstr_map24, i64 0, i32 0
  store i64 3, i64* %16, align 8
  %17 = add nsw i64 %"$x.2", -1
  %18 = getelementptr %printf_t.2, %printf_t.2* %lookup_fmtstr_map24, i64 0, i32 1
  store i64 %17, i64* %18, align 8
  %pseudo29 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %get_cpu_id30 = call i64 inttoptr (i64 8 to i64 ()*)()
  %perf_event_output31 = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %printf_t.2*, i64)*)(i8* %0, i64 %pseudo29, i64 %get_cpu_id30, %printf_t.2* nonnull %lookup_fmtstr_map24, i64 16)
  %19 = bitcast %printf_t.2* %lookup_fmtstr_map24 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %19)
  br label %fmtstrzero25
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
