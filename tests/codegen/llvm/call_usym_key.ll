; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

%bpf_pidns_info_t = type { i32, i32 }
%usym_t = type { i64, i64 }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

define i64 @"kprobe:f"(i8*) section "s_kprobe:f_1" {
entry:
  %"@x_val" = alloca i64
  %lookup_elem_val = alloca i64
  %bpf_pidns_info = alloca %bpf_pidns_info_t
  %usym = alloca %usym_t
  %1 = bitcast %usym_t* %usym to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  %2 = bitcast %bpf_pidns_info_t* %bpf_pidns_info to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %2)
  %get_ns_current_pid_tgid = call i64 inttoptr (i64 120 to i64 (i64, i64, %bpf_pidns_info_t*, i32)*)(i64 0, i64 0, %bpf_pidns_info_t* %bpf_pidns_info, i32 8)
  %3 = getelementptr %bpf_pidns_info_t, %bpf_pidns_info_t* %bpf_pidns_info, i32 0, i32 0
  %4 = load i32, i32* %3
  %5 = zext i32 %4 to i64
  %6 = getelementptr %bpf_pidns_info_t, %bpf_pidns_info_t* %bpf_pidns_info, i32 0, i32 1
  %7 = load i32, i32* %6
  %8 = zext i32 %7 to i64
  %9 = bitcast %bpf_pidns_info_t* %bpf_pidns_info to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %9)
  %10 = shl i64 %8, 32
  %11 = or i64 %10, %5
  %12 = lshr i64 %11, 32
  %13 = getelementptr %usym_t, %usym_t* %usym, i64 0, i32 0
  %14 = getelementptr %usym_t, %usym_t* %usym, i64 0, i32 1
  store i64 0, i64* %13
  store i64 %12, i64* %14
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i64, %usym_t*)*)(i64 %pseudo, %usym_t* %usym)
  %15 = bitcast i64* %lookup_elem_val to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %15)
  %map_lookup_cond = icmp ne i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  %cast = bitcast i8* %lookup_elem to i64*
  %16 = load i64, i64* %cast
  store i64 %16, i64* %lookup_elem_val
  br label %lookup_merge

lookup_failure:                                   ; preds = %entry
  store i64 0, i64* %lookup_elem_val
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  %17 = load i64, i64* %lookup_elem_val
  %18 = bitcast i64* %lookup_elem_val to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %18)
  %19 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %19)
  %20 = add i64 %17, 1
  store i64 %20, i64* %"@x_val"
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, %usym_t*, i64*, i64)*)(i64 %pseudo1, %usym_t* %usym, i64* %"@x_val", i64 0)
  %21 = bitcast %usym_t* %usym to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %21)
  %22 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %22)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
