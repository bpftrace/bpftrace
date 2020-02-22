; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"kprobe:f"(i8* nocapture readnone) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %"@x_key" = alloca i64, align 8
  %buf = alloca [64 x i8], align 1
  %1 = getelementptr inbounds [64 x i8], [64 x i8]* %buf, i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %get_pid_tgid = tail call i64 inttoptr (i64 14 to i64 ()*)()
  %2 = icmp ult i64 %get_pid_tgid, 42949672960000
  br i1 %2, label %left, label %right

left:                                             ; preds = %entry
  store i8 108, i8* %1, align 1
  %str.sroa.4.0..sroa_idx = getelementptr inbounds [64 x i8], [64 x i8]* %buf, i64 0, i64 1
  store i8 111, i8* %str.sroa.4.0..sroa_idx, align 1
  %str.sroa.5.0..sroa_idx = getelementptr inbounds [64 x i8], [64 x i8]* %buf, i64 0, i64 2
  call void @llvm.memset.p0i8.i64(i8* nonnull align 1 %str.sroa.5.0..sroa_idx, i8 0, i64 61, i1 false)
  br label %done

right:                                            ; preds = %entry
  store i8 104, i8* %1, align 1
  %str1.sroa.4.0..sroa_idx = getelementptr inbounds [64 x i8], [64 x i8]* %buf, i64 0, i64 1
  store i8 105, i8* %str1.sroa.4.0..sroa_idx, align 1
  %str1.sroa.5.0..sroa_idx = getelementptr inbounds [64 x i8], [64 x i8]* %buf, i64 0, i64 2
  call void @llvm.memset.p0i8.i64(i8* nonnull align 1 %str1.sroa.5.0..sroa_idx, i8 0, i64 61, i1 false)
  br label %done

done:                                             ; preds = %right, %left
  %3 = getelementptr inbounds [64 x i8], [64 x i8]* %buf, i64 0, i64 63
  store i8 0, i8* %3, align 1
  %4 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %4)
  store i64 0, i64* %"@x_key", align 8
  %pseudo = tail call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, [64 x i8]*, i64)*)(i64 %pseudo, i64* nonnull %"@x_key", [64 x i8]* nonnull %buf, i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %4)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
