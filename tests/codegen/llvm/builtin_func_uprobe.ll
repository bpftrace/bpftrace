; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

%bpf_pidns_info_t = type { i32, i32 }
%usym_t = type { i64, i64 }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

define i64 @"uprobe:/bin/sh:f"(i8*) section "s_uprobe:/bin/sh:f_1" {
entry:
  %"@x_key" = alloca i64
  %bpf_pidns_info = alloca %bpf_pidns_info_t
  %usym = alloca %usym_t
  %1 = bitcast i8* %0 to i64*
  %2 = getelementptr i64, i64* %1, i64 16
  %func = load volatile i64, i64* %2
  %3 = bitcast %usym_t* %usym to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %3)
  %4 = bitcast %bpf_pidns_info_t* %bpf_pidns_info to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %4)
  %get_ns_current_pid_tgid = call i64 inttoptr (i64 120 to i64 (i64, i64, %bpf_pidns_info_t*, i32)*)(i64 0, i64 0, %bpf_pidns_info_t* %bpf_pidns_info, i32 8)
  %5 = getelementptr %bpf_pidns_info_t, %bpf_pidns_info_t* %bpf_pidns_info, i32 0, i32 0
  %6 = load i32, i32* %5
  %7 = zext i32 %6 to i64
  %8 = getelementptr %bpf_pidns_info_t, %bpf_pidns_info_t* %bpf_pidns_info, i32 0, i32 1
  %9 = load i32, i32* %8
  %10 = zext i32 %9 to i64
  %11 = bitcast %bpf_pidns_info_t* %bpf_pidns_info to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %11)
  %12 = shl i64 %10, 32
  %13 = or i64 %12, %7
  %14 = lshr i64 %13, 32
  %15 = getelementptr %usym_t, %usym_t* %usym, i64 0, i32 0
  %16 = getelementptr %usym_t, %usym_t* %usym, i64 0, i32 1
  store i64 %func, i64* %15
  store i64 %14, i64* %16
  %17 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %17)
  store i64 0, i64* %"@x_key"
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, %usym_t*, i64)*)(i64 %pseudo, i64* %"@x_key", %usym_t* %usym, i64 0)
  %18 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %18)
  %19 = bitcast %usym_t* %usym to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %19)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
