; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

define i64 @"kprobe:f"(i8*) section "s_kprobe:f_1" {
entry:
  %"@x_val" = alloca i64
  %lookup_elem_val8 = alloca i64
  %"@x_key2" = alloca i64
  %"@x_num" = alloca i64
  %lookup_elem_val = alloca i64
  %"@x_key" = alloca i64
  %1 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 0, i64* %"@x_key"
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo, i64* %"@x_key")
  %2 = bitcast i64* %lookup_elem_val to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %2)
  %map_lookup_cond = icmp ne i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  %cast = bitcast i8* %lookup_elem to i64*
  %3 = load i64, i64* %cast
  store i64 %3, i64* %lookup_elem_val
  br label %lookup_merge

lookup_failure:                                   ; preds = %entry
  store i64 0, i64* %lookup_elem_val
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  %4 = load i64, i64* %lookup_elem_val
  %5 = bitcast i64* %lookup_elem_val to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %5)
  %6 = bitcast i64* %"@x_num" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %6)
  %7 = add i64 %4, 1
  store i64 %7, i64* %"@x_num"
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo1, i64* %"@x_key", i64* %"@x_num", i64 0)
  %8 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %8)
  %9 = bitcast i64* %"@x_num" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %9)
  %10 = bitcast i64* %"@x_key2" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %10)
  store i64 1, i64* %"@x_key2"
  %pseudo3 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem4 = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo3, i64* %"@x_key2")
  %11 = bitcast i64* %lookup_elem_val8 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %11)
  %map_lookup_cond9 = icmp ne i8* %lookup_elem4, null
  br i1 %map_lookup_cond9, label %lookup_success5, label %lookup_failure6

lookup_success5:                                  ; preds = %lookup_merge
  %cast10 = bitcast i8* %lookup_elem4 to i64*
  %12 = load i64, i64* %cast10
  store i64 %12, i64* %lookup_elem_val8
  br label %lookup_merge7

lookup_failure6:                                  ; preds = %lookup_merge
  store i64 0, i64* %lookup_elem_val8
  br label %lookup_merge7

lookup_merge7:                                    ; preds = %lookup_failure6, %lookup_success5
  %13 = load i64, i64* %lookup_elem_val8
  %14 = bitcast i64* %lookup_elem_val8 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %14)
  %15 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %15)
  %get_pid_tgid = call i64 inttoptr (i64 14 to i64 ()*)()
  %16 = lshr i64 %get_pid_tgid, 32
  %17 = add i64 %16, %13
  store i64 %17, i64* %"@x_val"
  %pseudo11 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem12 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo11, i64* %"@x_key2", i64* %"@x_val", i64 0)
  %18 = bitcast i64* %"@x_key2" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %18)
  %19 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %19)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
