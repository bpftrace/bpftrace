; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: norecurse nounwind readnone
define i64 @"kprobe:f"(i8* nocapture readnone) local_unnamed_addr #0 section "s_kprobe:f_1" {
entry:
  ret i64 0
}

attributes #0 = { norecurse nounwind readnone }
