; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"uprobe:/bin/sh:f"(i8* nocapture readonly) local_unnamed_addr section "s_uprobe:/bin/sh:f_1" {
entry:
  %"@x_val" = alloca [16 x i8], align 8
  %"@x_key" = alloca i64, align 8
  %func1 = alloca [16 x i8], align 8
  %1 = getelementptr i8, i8* %0, i64 128
  %func = load i64, i8* %1, align 8
  %2 = getelementptr inbounds [16 x i8], [16 x i8]* %func1, i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %2)
  %get_pid_tgid = tail call i64 inttoptr (i64 14 to i64 ()*)()
  %3 = lshr i64 %get_pid_tgid, 32
  %4 = getelementptr inbounds [16 x i8], [16 x i8]* %func1, i64 0, i64 8
  store i64 %func, [16 x i8]* %func1, align 8
  store i64 %3, i8* %4, align 8
  %5 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %5)
  store i64 0, i64* %"@x_key", align 8
  %6 = getelementptr inbounds [16 x i8], [16 x i8]* %"@x_val", i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %6)
  store [16 x i8]* %func1, [16 x i8]* %"@x_val", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, [16 x i8]*, i64)*)(i64 %pseudo, i64* nonnull %"@x_key", [16 x i8]* nonnull %"@x_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %5)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %6)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
