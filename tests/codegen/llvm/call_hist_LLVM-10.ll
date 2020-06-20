; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"kprobe:f"(i8* nocapture readnone %0) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %"@x_val" = alloca i64, align 8
  %"@x_key" = alloca i64, align 8
  %get_pid_tgid = tail call i64 inttoptr (i64 14 to i64 ()*)()
  %1 = lshr i64 %get_pid_tgid, 32
  %2 = icmp eq i64 %1, 0
  br i1 %2, label %log2.exit, label %hist.is_not_zero.i

hist.is_not_zero.i:                               ; preds = %entry
  %3 = icmp ugt i64 %get_pid_tgid, 281474976710655
  %4 = select i1 %3, i64 16, i64 0
  %5 = lshr i64 %1, %4
  %6 = icmp sgt i64 %5, 255
  %7 = select i1 %6, i64 8, i64 0
  %8 = lshr i64 %5, %7
  %9 = icmp sgt i64 %8, 15
  %10 = select i1 %9, i64 4, i64 0
  %11 = lshr i64 %8, %10
  %12 = or i64 %4, %7
  %13 = or i64 %12, %10
  %14 = or i64 %13, 2
  %15 = icmp sgt i64 %11, 3
  %16 = select i1 %15, i64 2, i64 0
  %17 = lshr i64 %11, %16
  %18 = add nuw nsw i64 %16, %14
  %19 = icmp sgt i64 %17, 1
  %20 = zext i1 %19 to i64
  %21 = or i64 %18, %20
  br label %log2.exit

log2.exit:                                        ; preds = %entry, %hist.is_not_zero.i
  %log22 = phi i64 [ %21, %hist.is_not_zero.i ], [ 1, %entry ]
  %22 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %22)
  store i64 %log22, i64* %"@x_key", align 8
  %pseudo = tail call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo, i64* nonnull %"@x_key")
  %map_lookup_cond = icmp eq i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_merge, label %lookup_success

lookup_success:                                   ; preds = %log2.exit
  %cast = bitcast i8* %lookup_elem to i64*
  %23 = load i64, i64* %cast, align 8
  %phitmp = add i64 %23, 1
  br label %lookup_merge

lookup_merge:                                     ; preds = %log2.exit, %lookup_success
  %lookup_elem_val.0 = phi i64 [ %phitmp, %lookup_success ], [ 1, %log2.exit ]
  %24 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %24)
  store i64 %lookup_elem_val.0, i64* %"@x_val", align 8
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo1, i64* nonnull %"@x_key", i64* nonnull %"@x_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %22)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %24)
  ret i64 0
}

; Function Attrs: argmemonly nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind willreturn }
