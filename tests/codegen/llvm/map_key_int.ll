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
  %"@x_val" = alloca i64, align 8
  %"@x_key" = alloca [24 x i8], align 8
  %1 = getelementptr inbounds [24 x i8], [24 x i8]* %"@x_key", i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %2 = bitcast [24 x i8]* %"@x_key" to i64*
  store i64 11, i64* %2, align 8
  %3 = getelementptr inbounds [24 x i8], [24 x i8]* %"@x_key", i64 0, i64 8
  %4 = bitcast i8* %3 to i64*
  store i64 22, i64* %4, align 8
  %5 = getelementptr inbounds [24 x i8], [24 x i8]* %"@x_key", i64 0, i64 16
  %6 = bitcast i8* %5 to i64*
  store i64 33, i64* %6, align 8
  %7 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %7)
  store i64 44, i64* %"@x_val", align 8
  %pseudo = tail call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, [24 x i8]*, i64*, i64)*)(i64 %pseudo, [24 x i8]* nonnull %"@x_key", i64* nonnull %"@x_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %7)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
