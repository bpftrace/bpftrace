; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

define i64 @BEGIN(i8* nocapture readnone) local_unnamed_addr section "s_BEGIN_1" {
entry:
  %"@x_newval38" = alloca i64, align 8
  %"@x_key29" = alloca i64, align 8
  %"@x_newval26" = alloca i64, align 8
  %"@x_key17" = alloca i64, align 8
  %"@x_newval14" = alloca i64, align 8
  %"@x_key5" = alloca i64, align 8
  %"@x_newval" = alloca i64, align 8
  %"@x_key1" = alloca i64, align 8
  %"@x_val" = alloca i64, align 8
  %"@x_key" = alloca i64, align 8
  %1 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  store i64 0, i64* %"@x_key", align 8
  %2 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %2)
  store i64 10, i64* %"@x_val", align 8
  %pseudo = tail call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo, i64* nonnull %"@x_key", i64* nonnull %"@x_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %2)
  %3 = bitcast i64* %"@x_key1" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %3)
  store i64 0, i64* %"@x_key1", align 8
  %pseudo2 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo2, i64* nonnull %"@x_key1")
  %map_lookup_cond = icmp eq i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_merge, label %lookup_success

lookup_success:                                   ; preds = %entry
  %cast = bitcast i8* %lookup_elem to i64*
  %4 = load i64, i64* %cast, align 8
  %phitmp = add i64 %4, 1
  br label %lookup_merge

lookup_merge:                                     ; preds = %entry, %lookup_success
  %lookup_elem_val.0 = phi i64 [ %phitmp, %lookup_success ], [ 1, %entry ]
  %5 = bitcast i64* %"@x_newval" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %5)
  store i64 %lookup_elem_val.0, i64* %"@x_newval", align 8
  %pseudo3 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem4 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo3, i64* nonnull %"@x_key1", i64* nonnull %"@x_newval", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %3)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %5)
  %6 = bitcast i64* %"@x_key5" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %6)
  store i64 0, i64* %"@x_key5", align 8
  %pseudo6 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem7 = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo6, i64* nonnull %"@x_key5")
  %map_lookup_cond12 = icmp eq i8* %lookup_elem7, null
  br i1 %map_lookup_cond12, label %lookup_merge10, label %lookup_success8

lookup_success8:                                  ; preds = %lookup_merge
  %cast13 = bitcast i8* %lookup_elem7 to i64*
  %7 = load i64, i64* %cast13, align 8
  %phitmp41 = add i64 %7, 1
  br label %lookup_merge10

lookup_merge10:                                   ; preds = %lookup_merge, %lookup_success8
  %lookup_elem_val11.0 = phi i64 [ %phitmp41, %lookup_success8 ], [ 1, %lookup_merge ]
  %8 = bitcast i64* %"@x_newval14" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %8)
  store i64 %lookup_elem_val11.0, i64* %"@x_newval14", align 8
  %pseudo15 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem16 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo15, i64* nonnull %"@x_key5", i64* nonnull %"@x_newval14", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %6)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %8)
  %9 = bitcast i64* %"@x_key17" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %9)
  store i64 0, i64* %"@x_key17", align 8
  %pseudo18 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem19 = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo18, i64* nonnull %"@x_key17")
  %map_lookup_cond24 = icmp eq i8* %lookup_elem19, null
  br i1 %map_lookup_cond24, label %lookup_merge22, label %lookup_success20

lookup_success20:                                 ; preds = %lookup_merge10
  %cast25 = bitcast i8* %lookup_elem19 to i64*
  %10 = load i64, i64* %cast25, align 8
  %phitmp42 = add i64 %10, -1
  br label %lookup_merge22

lookup_merge22:                                   ; preds = %lookup_merge10, %lookup_success20
  %lookup_elem_val23.0 = phi i64 [ %phitmp42, %lookup_success20 ], [ -1, %lookup_merge10 ]
  %11 = bitcast i64* %"@x_newval26" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %11)
  store i64 %lookup_elem_val23.0, i64* %"@x_newval26", align 8
  %pseudo27 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem28 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo27, i64* nonnull %"@x_key17", i64* nonnull %"@x_newval26", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %9)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %11)
  %12 = bitcast i64* %"@x_key29" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %12)
  store i64 0, i64* %"@x_key29", align 8
  %pseudo30 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem31 = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo30, i64* nonnull %"@x_key29")
  %map_lookup_cond36 = icmp eq i8* %lookup_elem31, null
  br i1 %map_lookup_cond36, label %lookup_merge34, label %lookup_success32

lookup_success32:                                 ; preds = %lookup_merge22
  %cast37 = bitcast i8* %lookup_elem31 to i64*
  %13 = load i64, i64* %cast37, align 8
  %phitmp43 = add i64 %13, -1
  br label %lookup_merge34

lookup_merge34:                                   ; preds = %lookup_merge22, %lookup_success32
  %lookup_elem_val35.0 = phi i64 [ %phitmp43, %lookup_success32 ], [ -1, %lookup_merge22 ]
  %14 = bitcast i64* %"@x_newval38" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %14)
  store i64 %lookup_elem_val35.0, i64* %"@x_newval38", align 8
  %pseudo39 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem40 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo39, i64* nonnull %"@x_key29", i64* nonnull %"@x_newval38", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %12)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %14)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
