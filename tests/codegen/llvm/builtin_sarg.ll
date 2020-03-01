; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"kprobe:f"(i8*) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %"@y_val" = alloca i64, align 8
  %"@y_key" = alloca i64, align 8
  %sarg2 = alloca i64, align 8
  %"@x_val" = alloca i64, align 8
  %"@x_key" = alloca i64, align 8
  %sarg0 = alloca i64, align 8
  %1 = getelementptr i8, i8* %0, i64 152
  %2 = bitcast i8* %1 to i64*
  %reg_sp = load volatile i64, i64* %2, align 8
  %3 = bitcast i64* %sarg0 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %3)
  %4 = add i64 %reg_sp, 8
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i64* nonnull %sarg0, i64 8, i64 %4)
  %5 = load i64, i64* %sarg0, align 8
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %3)
  %6 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %6)
  store i64 0, i64* %"@x_key", align 8
  %7 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %7)
  store i64 %5, i64* %"@x_val", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo, i64* nonnull %"@x_key", i64* nonnull %"@x_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %6)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %7)
  %reg_sp1 = load volatile i64, i64* %2, align 8
  %8 = bitcast i64* %sarg2 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %8)
  %9 = add i64 %reg_sp1, 24
  %probe_read2 = call i64 inttoptr (i64 4 to i64 (i8*, i64, i8*)*)(i64* nonnull %sarg2, i64 8, i64 %9)
  %10 = load i64, i64* %sarg2, align 8
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %8)
  %11 = bitcast i64* %"@y_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %11)
  store i64 0, i64* %"@y_key", align 8
  %12 = bitcast i64* %"@y_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %12)
  store i64 %10, i64* %"@y_val", align 8
  %pseudo3 = call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  %update_elem4 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo3, i64* nonnull %"@y_key", i64* nonnull %"@y_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %11)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %12)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
