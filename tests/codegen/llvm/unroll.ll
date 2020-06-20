; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

define i64 @BEGIN(i8* nocapture readnone) local_unnamed_addr section "s_BEGIN_1" {
entry:
  %"@i_val56" = alloca i64, align 8
  %"@i_key55" = alloca i64, align 8
  %"@i_key46" = alloca i64, align 8
  %"@i_val43" = alloca i64, align 8
  %"@i_key42" = alloca i64, align 8
  %"@i_key33" = alloca i64, align 8
  %"@i_val30" = alloca i64, align 8
  %"@i_key29" = alloca i64, align 8
  %"@i_key20" = alloca i64, align 8
  %"@i_val17" = alloca i64, align 8
  %"@i_key16" = alloca i64, align 8
  %"@i_key7" = alloca i64, align 8
  %"@i_val4" = alloca i64, align 8
  %"@i_key3" = alloca i64, align 8
  %"@i_key1" = alloca i64, align 8
  %"@i_val" = alloca i64, align 8
  %"@i_key" = alloca i64, align 8
  %1 = bitcast i64* %"@i_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  store i64 0, i64* %"@i_key", align 8
  %2 = bitcast i64* %"@i_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %2)
  store i64 0, i64* %"@i_val", align 8
  %pseudo = tail call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo, i64* nonnull %"@i_key", i64* nonnull %"@i_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %2)
  %3 = bitcast i64* %"@i_key1" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %3)
  store i64 0, i64* %"@i_key1", align 8
  %pseudo2 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo2, i64* nonnull %"@i_key1")
  %map_lookup_cond = icmp eq i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_merge, label %lookup_success

lookup_success:                                   ; preds = %entry
  %cast = bitcast i8* %lookup_elem to i64*
  %4 = load i64, i64* %cast, align 8
  %phitmp = add i64 %4, 1
  br label %lookup_merge

lookup_merge:                                     ; preds = %entry, %lookup_success
  %lookup_elem_val.0 = phi i64 [ %phitmp, %lookup_success ], [ 1, %entry ]
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %3)
  %5 = bitcast i64* %"@i_key3" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %5)
  store i64 0, i64* %"@i_key3", align 8
  %6 = bitcast i64* %"@i_val4" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %6)
  store i64 %lookup_elem_val.0, i64* %"@i_val4", align 8
  %pseudo5 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem6 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo5, i64* nonnull %"@i_key3", i64* nonnull %"@i_val4", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %5)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %6)
  %7 = bitcast i64* %"@i_key7" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %7)
  store i64 0, i64* %"@i_key7", align 8
  %pseudo8 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem9 = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo8, i64* nonnull %"@i_key7")
  %map_lookup_cond14 = icmp eq i8* %lookup_elem9, null
  br i1 %map_lookup_cond14, label %lookup_merge12, label %lookup_success10

lookup_success10:                                 ; preds = %lookup_merge
  %cast15 = bitcast i8* %lookup_elem9 to i64*
  %8 = load i64, i64* %cast15, align 8
  %phitmp59 = add i64 %8, 1
  br label %lookup_merge12

lookup_merge12:                                   ; preds = %lookup_merge, %lookup_success10
  %lookup_elem_val13.0 = phi i64 [ %phitmp59, %lookup_success10 ], [ 1, %lookup_merge ]
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %7)
  %9 = bitcast i64* %"@i_key16" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %9)
  store i64 0, i64* %"@i_key16", align 8
  %10 = bitcast i64* %"@i_val17" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %10)
  store i64 %lookup_elem_val13.0, i64* %"@i_val17", align 8
  %pseudo18 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem19 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo18, i64* nonnull %"@i_key16", i64* nonnull %"@i_val17", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %9)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %10)
  %11 = bitcast i64* %"@i_key20" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %11)
  store i64 0, i64* %"@i_key20", align 8
  %pseudo21 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem22 = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo21, i64* nonnull %"@i_key20")
  %map_lookup_cond27 = icmp eq i8* %lookup_elem22, null
  br i1 %map_lookup_cond27, label %lookup_merge25, label %lookup_success23

lookup_success23:                                 ; preds = %lookup_merge12
  %cast28 = bitcast i8* %lookup_elem22 to i64*
  %12 = load i64, i64* %cast28, align 8
  %phitmp60 = add i64 %12, 1
  br label %lookup_merge25

lookup_merge25:                                   ; preds = %lookup_merge12, %lookup_success23
  %lookup_elem_val26.0 = phi i64 [ %phitmp60, %lookup_success23 ], [ 1, %lookup_merge12 ]
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %11)
  %13 = bitcast i64* %"@i_key29" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %13)
  store i64 0, i64* %"@i_key29", align 8
  %14 = bitcast i64* %"@i_val30" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %14)
  store i64 %lookup_elem_val26.0, i64* %"@i_val30", align 8
  %pseudo31 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem32 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo31, i64* nonnull %"@i_key29", i64* nonnull %"@i_val30", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %13)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %14)
  %15 = bitcast i64* %"@i_key33" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %15)
  store i64 0, i64* %"@i_key33", align 8
  %pseudo34 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem35 = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo34, i64* nonnull %"@i_key33")
  %map_lookup_cond40 = icmp eq i8* %lookup_elem35, null
  br i1 %map_lookup_cond40, label %lookup_merge38, label %lookup_success36

lookup_success36:                                 ; preds = %lookup_merge25
  %cast41 = bitcast i8* %lookup_elem35 to i64*
  %16 = load i64, i64* %cast41, align 8
  %phitmp61 = add i64 %16, 1
  br label %lookup_merge38

lookup_merge38:                                   ; preds = %lookup_merge25, %lookup_success36
  %lookup_elem_val39.0 = phi i64 [ %phitmp61, %lookup_success36 ], [ 1, %lookup_merge25 ]
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %15)
  %17 = bitcast i64* %"@i_key42" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %17)
  store i64 0, i64* %"@i_key42", align 8
  %18 = bitcast i64* %"@i_val43" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %18)
  store i64 %lookup_elem_val39.0, i64* %"@i_val43", align 8
  %pseudo44 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem45 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo44, i64* nonnull %"@i_key42", i64* nonnull %"@i_val43", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %17)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %18)
  %19 = bitcast i64* %"@i_key46" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %19)
  store i64 0, i64* %"@i_key46", align 8
  %pseudo47 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem48 = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo47, i64* nonnull %"@i_key46")
  %map_lookup_cond53 = icmp eq i8* %lookup_elem48, null
  br i1 %map_lookup_cond53, label %lookup_merge51, label %lookup_success49

lookup_success49:                                 ; preds = %lookup_merge38
  %cast54 = bitcast i8* %lookup_elem48 to i64*
  %20 = load i64, i64* %cast54, align 8
  %phitmp62 = add i64 %20, 1
  br label %lookup_merge51

lookup_merge51:                                   ; preds = %lookup_merge38, %lookup_success49
  %lookup_elem_val52.0 = phi i64 [ %phitmp62, %lookup_success49 ], [ 1, %lookup_merge38 ]
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %19)
  %21 = bitcast i64* %"@i_key55" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %21)
  store i64 0, i64* %"@i_key55", align 8
  %22 = bitcast i64* %"@i_val56" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %22)
  store i64 %lookup_elem_val52.0, i64* %"@i_val56", align 8
  %pseudo57 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem58 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo57, i64* nonnull %"@i_key55", i64* nonnull %"@i_val56", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %21)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %22)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
