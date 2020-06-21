; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

define i64 @"kprobe:f"(i8*) section "s_kprobe:f_1" {
entry:
  ret i64 0
}

define i64 @"kprobe:f.1"(i8*) section "s_kprobe:f_2" {
entry:
  ret i64 0
}

attributes #0 = { nounwind }
