; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

%bpf_pidns_info_t = type { i32, i32 }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

define i64 @"kprobe:f"(i8*) section "s_kprobe:f_1" {
entry:
  %"@y_val" = alloca i64
  %"@y_key" = alloca i64
  %bpf_pidns_info4 = alloca %bpf_pidns_info_t
  %"@x_val" = alloca i64
  %"@x_key" = alloca i64
  %bpf_pidns_info = alloca %bpf_pidns_info_t
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 4)
  %get_stackid = call i64 inttoptr (i64 27 to i64 (i8*, i64, i64)*)(i8* %0, i64 %pseudo, i64 256)
  %1 = bitcast %bpf_pidns_info_t* %bpf_pidns_info to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  %get_ns_current_pid_tgid = call i64 inttoptr (i64 120 to i64 (i64, i64, %bpf_pidns_info_t*, i32)*)(i64 0, i64 0, %bpf_pidns_info_t* %bpf_pidns_info, i32 8)
  %2 = getelementptr %bpf_pidns_info_t, %bpf_pidns_info_t* %bpf_pidns_info, i32 0, i32 0
  %3 = load i32, i32* %2
  %4 = zext i32 %3 to i64
  %5 = getelementptr %bpf_pidns_info_t, %bpf_pidns_info_t* %bpf_pidns_info, i32 0, i32 1
  %6 = load i32, i32* %5
  %7 = zext i32 %6 to i64
  %8 = bitcast %bpf_pidns_info_t* %bpf_pidns_info to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %8)
  %9 = shl i64 %7, 32
  %10 = or i64 %9, %4
  %11 = shl i64 %10, 32
  %12 = or i64 %get_stackid, %11
  %13 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %13)
  store i64 0, i64* %"@x_key"
  %14 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %14)
  store i64 %12, i64* %"@x_val"
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo1, i64* %"@x_key", i64* %"@x_val", i64 0)
  %15 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %15)
  %16 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %16)
  %pseudo2 = call i64 @llvm.bpf.pseudo(i64 1, i64 3)
  %get_stackid3 = call i64 inttoptr (i64 27 to i64 (i8*, i64, i64)*)(i8* %0, i64 %pseudo2, i64 256)
  %17 = bitcast %bpf_pidns_info_t* %bpf_pidns_info4 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %17)
  %get_ns_current_pid_tgid5 = call i64 inttoptr (i64 120 to i64 (i64, i64, %bpf_pidns_info_t*, i32)*)(i64 0, i64 0, %bpf_pidns_info_t* %bpf_pidns_info4, i32 8)
  %18 = getelementptr %bpf_pidns_info_t, %bpf_pidns_info_t* %bpf_pidns_info4, i32 0, i32 0
  %19 = load i32, i32* %18
  %20 = zext i32 %19 to i64
  %21 = getelementptr %bpf_pidns_info_t, %bpf_pidns_info_t* %bpf_pidns_info4, i32 0, i32 1
  %22 = load i32, i32* %21
  %23 = zext i32 %22 to i64
  %24 = bitcast %bpf_pidns_info_t* %bpf_pidns_info4 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %24)
  %25 = shl i64 %23, 32
  %26 = or i64 %25, %20
  %27 = shl i64 %26, 32
  %28 = or i64 %get_stackid3, %27
  %29 = bitcast i64* %"@y_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %29)
  store i64 0, i64* %"@y_key"
  %30 = bitcast i64* %"@y_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %30)
  store i64 %28, i64* %"@y_val"
  %pseudo6 = call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  %update_elem7 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo6, i64* %"@y_key", i64* %"@y_val", i64 0)
  %31 = bitcast i64* %"@y_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %31)
  %32 = bitcast i64* %"@y_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %32)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
