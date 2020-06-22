; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

define i64 @"kretprobe:f"(i8*) local_unnamed_addr section "s_kretprobe:f_1" {
entry:
  %"@_val" = alloca i64, align 8
  %"@_key" = alloca i64, align 8
  %deref = alloca i8, align 1
  %1 = getelementptr i8, i8* %0, i64 32
  %2 = bitcast i8* %1 to i64*
  %reg_bp = load volatile i64, i64* %2, align 8
  %3 = add i64 %reg_bp, -1
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %deref)
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i32, i64)*)(i8* nonnull %deref, i32 1, i64 %3)
  %4 = load i8, i8* %deref, align 1
  %5 = sext i8 %4 to i64
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %deref)
  %6 = bitcast i64* %"@_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %6)
  store i64 0, i64* %"@_key", align 8
  %7 = bitcast i64* %"@_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %7)
  store i64 %5, i64* %"@_val", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo, i64* nonnull %"@_key", i64* nonnull %"@_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %6)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %7)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
