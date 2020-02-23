; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

define i64 @"kprobe:f"(i8*) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %1 = getelementptr i8, i8* %0, i64 112
  %2 = bitcast i8* %1 to i64*
  %arg0 = load volatile i64, i64* %2, align 8
  %3 = trunc i64 %arg0 to i32
  %signal = tail call i64 inttoptr (i64 109 to i64 (i32)*)(i32 %3)
  ret i64 0
}
