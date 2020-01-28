; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

define i64 @"kprobe:f"(i8*) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %1 = getelementptr i8, i8* %0, i64 112
  %arg0 = load volatile i64, i8* %1, align 8
  %override = tail call i64 inttoptr (i64 58 to i64 (i8*, i64)*)(i8* %0, i64 %arg0)
  ret i64 0
}
