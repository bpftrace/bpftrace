; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"kprobe:f"(i8* %0) section "s_kprobe:f_1" {
entry:
  %key = alloca i32, align 4
  %join_r0 = alloca i64, align 8
  %lookup_join_key = alloca i32, align 4
  %"struct arg.argv" = alloca i64, align 8
  %"$x" = alloca i64, align 8
  %1 = bitcast i64* %"$x" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 0, i64* %"$x", align 8
  store i64 0, i64* %"$x", align 8
  %2 = load i64, i64* %"$x", align 8
  %3 = add i64 %2, 0
  %4 = bitcast i64* %"struct arg.argv" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %4)
  %probe_read_kernel = call i64 inttoptr (i64 113 to i64 (i64*, i32, i64)*)(i64* %"struct arg.argv", i32 8, i64 %3)
  %5 = load i64, i64* %"struct arg.argv", align 8
  %6 = bitcast i64* %"struct arg.argv" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %6)
  %7 = bitcast i32* %lookup_join_key to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %7)
  store i32 0, i32* %lookup_join_key, align 4
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %lookup_join_map = call i8* inttoptr (i64 1 to i8* (i64, i32*)*)(i64 %pseudo, i32* %lookup_join_key)
  %8 = bitcast i32* %lookup_join_key to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %8)
  %lookup_join_cond = icmp ne i8* %lookup_join_map, null
  br i1 %lookup_join_cond, label %lookup_join_merge, label %lookup_join_failure

failure_callback:                                 ; preds = %counter_merge, %lookup_join_failure
  ret i64 0

lookup_join_failure:                              ; preds = %entry
  br label %failure_callback

lookup_join_merge:                                ; preds = %entry
  %9 = bitcast i8* %lookup_join_map to i64*
  store i64 30005, i64* %9, align 8
  %10 = getelementptr i8, i8* %lookup_join_map, i64 8
  %11 = bitcast i8* %10 to i64*
  store i64 0, i64* %11, align 8
  %12 = bitcast i64* %join_r0 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %12)
  %probe_read_kernel1 = call i64 inttoptr (i64 113 to i64 (i64*, i32, i64)*)(i64* %join_r0, i32 8, i64 %5)
  %13 = load i64, i64* %join_r0, align 8
  %14 = getelementptr i8, i8* %lookup_join_map, i64 16
  %probe_read_kernel_str = call i64 inttoptr (i64 115 to i64 (i8*, i32, i64)*)(i8* %14, i32 1024, i64 %13)
  %15 = add i64 %5, 8
  %probe_read_kernel2 = call i64 inttoptr (i64 113 to i64 (i64*, i32, i64)*)(i64* %join_r0, i32 8, i64 %15)
  %16 = load i64, i64* %join_r0, align 8
  %17 = getelementptr i8, i8* %lookup_join_map, i64 1040
  %probe_read_kernel_str3 = call i64 inttoptr (i64 115 to i64 (i8*, i32, i64)*)(i8* %17, i32 1024, i64 %16)
  %18 = add i64 %15, 8
  %probe_read_kernel4 = call i64 inttoptr (i64 113 to i64 (i64*, i32, i64)*)(i64* %join_r0, i32 8, i64 %18)
  %19 = load i64, i64* %join_r0, align 8
  %20 = getelementptr i8, i8* %lookup_join_map, i64 2064
  %probe_read_kernel_str5 = call i64 inttoptr (i64 115 to i64 (i8*, i32, i64)*)(i8* %20, i32 1024, i64 %19)
  %21 = add i64 %18, 8
  %probe_read_kernel6 = call i64 inttoptr (i64 113 to i64 (i64*, i32, i64)*)(i64* %join_r0, i32 8, i64 %21)
  %22 = load i64, i64* %join_r0, align 8
  %23 = getelementptr i8, i8* %lookup_join_map, i64 3088
  %probe_read_kernel_str7 = call i64 inttoptr (i64 115 to i64 (i8*, i32, i64)*)(i8* %23, i32 1024, i64 %22)
  %24 = add i64 %21, 8
  %probe_read_kernel8 = call i64 inttoptr (i64 113 to i64 (i64*, i32, i64)*)(i64* %join_r0, i32 8, i64 %24)
  %25 = load i64, i64* %join_r0, align 8
  %26 = getelementptr i8, i8* %lookup_join_map, i64 4112
  %probe_read_kernel_str9 = call i64 inttoptr (i64 115 to i64 (i8*, i32, i64)*)(i8* %26, i32 1024, i64 %25)
  %27 = add i64 %24, 8
  %probe_read_kernel10 = call i64 inttoptr (i64 113 to i64 (i64*, i32, i64)*)(i64* %join_r0, i32 8, i64 %27)
  %28 = load i64, i64* %join_r0, align 8
  %29 = getelementptr i8, i8* %lookup_join_map, i64 5136
  %probe_read_kernel_str11 = call i64 inttoptr (i64 115 to i64 (i8*, i32, i64)*)(i8* %29, i32 1024, i64 %28)
  %30 = add i64 %27, 8
  %probe_read_kernel12 = call i64 inttoptr (i64 113 to i64 (i64*, i32, i64)*)(i64* %join_r0, i32 8, i64 %30)
  %31 = load i64, i64* %join_r0, align 8
  %32 = getelementptr i8, i8* %lookup_join_map, i64 6160
  %probe_read_kernel_str13 = call i64 inttoptr (i64 115 to i64 (i8*, i32, i64)*)(i8* %32, i32 1024, i64 %31)
  %33 = add i64 %30, 8
  %probe_read_kernel14 = call i64 inttoptr (i64 113 to i64 (i64*, i32, i64)*)(i64* %join_r0, i32 8, i64 %33)
  %34 = load i64, i64* %join_r0, align 8
  %35 = getelementptr i8, i8* %lookup_join_map, i64 7184
  %probe_read_kernel_str15 = call i64 inttoptr (i64 115 to i64 (i8*, i32, i64)*)(i8* %35, i32 1024, i64 %34)
  %36 = add i64 %33, 8
  %probe_read_kernel16 = call i64 inttoptr (i64 113 to i64 (i64*, i32, i64)*)(i64* %join_r0, i32 8, i64 %36)
  %37 = load i64, i64* %join_r0, align 8
  %38 = getelementptr i8, i8* %lookup_join_map, i64 8208
  %probe_read_kernel_str17 = call i64 inttoptr (i64 115 to i64 (i8*, i32, i64)*)(i8* %38, i32 1024, i64 %37)
  %39 = add i64 %36, 8
  %probe_read_kernel18 = call i64 inttoptr (i64 113 to i64 (i64*, i32, i64)*)(i64* %join_r0, i32 8, i64 %39)
  %40 = load i64, i64* %join_r0, align 8
  %41 = getelementptr i8, i8* %lookup_join_map, i64 9232
  %probe_read_kernel_str19 = call i64 inttoptr (i64 115 to i64 (i8*, i32, i64)*)(i8* %41, i32 1024, i64 %40)
  %42 = add i64 %39, 8
  %probe_read_kernel20 = call i64 inttoptr (i64 113 to i64 (i64*, i32, i64)*)(i64* %join_r0, i32 8, i64 %42)
  %43 = load i64, i64* %join_r0, align 8
  %44 = getelementptr i8, i8* %lookup_join_map, i64 10256
  %probe_read_kernel_str21 = call i64 inttoptr (i64 115 to i64 (i8*, i32, i64)*)(i8* %44, i32 1024, i64 %43)
  %45 = add i64 %42, 8
  %probe_read_kernel22 = call i64 inttoptr (i64 113 to i64 (i64*, i32, i64)*)(i64* %join_r0, i32 8, i64 %45)
  %46 = load i64, i64* %join_r0, align 8
  %47 = getelementptr i8, i8* %lookup_join_map, i64 11280
  %probe_read_kernel_str23 = call i64 inttoptr (i64 115 to i64 (i8*, i32, i64)*)(i8* %47, i32 1024, i64 %46)
  %48 = add i64 %45, 8
  %probe_read_kernel24 = call i64 inttoptr (i64 113 to i64 (i64*, i32, i64)*)(i64* %join_r0, i32 8, i64 %48)
  %49 = load i64, i64* %join_r0, align 8
  %50 = getelementptr i8, i8* %lookup_join_map, i64 12304
  %probe_read_kernel_str25 = call i64 inttoptr (i64 115 to i64 (i8*, i32, i64)*)(i8* %50, i32 1024, i64 %49)
  %51 = add i64 %48, 8
  %probe_read_kernel26 = call i64 inttoptr (i64 113 to i64 (i64*, i32, i64)*)(i64* %join_r0, i32 8, i64 %51)
  %52 = load i64, i64* %join_r0, align 8
  %53 = getelementptr i8, i8* %lookup_join_map, i64 13328
  %probe_read_kernel_str27 = call i64 inttoptr (i64 115 to i64 (i8*, i32, i64)*)(i8* %53, i32 1024, i64 %52)
  %54 = add i64 %51, 8
  %probe_read_kernel28 = call i64 inttoptr (i64 113 to i64 (i64*, i32, i64)*)(i64* %join_r0, i32 8, i64 %54)
  %55 = load i64, i64* %join_r0, align 8
  %56 = getelementptr i8, i8* %lookup_join_map, i64 14352
  %probe_read_kernel_str29 = call i64 inttoptr (i64 115 to i64 (i8*, i32, i64)*)(i8* %56, i32 1024, i64 %55)
  %57 = add i64 %54, 8
  %probe_read_kernel30 = call i64 inttoptr (i64 113 to i64 (i64*, i32, i64)*)(i64* %join_r0, i32 8, i64 %57)
  %58 = load i64, i64* %join_r0, align 8
  %59 = getelementptr i8, i8* %lookup_join_map, i64 15376
  %probe_read_kernel_str31 = call i64 inttoptr (i64 115 to i64 (i8*, i32, i64)*)(i8* %59, i32 1024, i64 %58)
  %pseudo32 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %ringbuf_output = call i64 inttoptr (i64 130 to i64 (i64, i8*, i64, i64)*)(i64 %pseudo32, i8* %lookup_join_map, i64 16400, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

event_loss_counter:                               ; preds = %lookup_join_merge
  %60 = bitcast i32* %key to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %60)
  store i32 0, i32* %key, align 4
  %pseudo33 = call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i64, i32*)*)(i64 %pseudo33, i32* %key)
  %map_lookup_cond = icmp ne i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

counter_merge:                                    ; preds = %lookup_merge, %lookup_join_merge
  br label %failure_callback

lookup_success:                                   ; preds = %event_loss_counter
  %61 = bitcast i8* %lookup_elem to i64*
  %62 = atomicrmw add i64* %61, i64 1 seq_cst
  br label %lookup_merge

lookup_failure:                                   ; preds = %event_loss_counter
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  %63 = bitcast i32* %key to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %63)
  br label %counter_merge
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }
