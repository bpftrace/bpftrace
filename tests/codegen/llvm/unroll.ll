; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @BEGIN(i8* %0) section "s_BEGIN_1" {
entry:
  %"@i_val56" = alloca i64, align 8
  %"@i_key55" = alloca i64, align 8
  %lookup_elem_val52 = alloca i64, align 8
  %"@i_key46" = alloca i64, align 8
  %"@i_val43" = alloca i64, align 8
  %"@i_key42" = alloca i64, align 8
  %lookup_elem_val39 = alloca i64, align 8
  %"@i_key33" = alloca i64, align 8
  %"@i_val30" = alloca i64, align 8
  %"@i_key29" = alloca i64, align 8
  %lookup_elem_val26 = alloca i64, align 8
  %"@i_key20" = alloca i64, align 8
  %"@i_val17" = alloca i64, align 8
  %"@i_key16" = alloca i64, align 8
  %lookup_elem_val13 = alloca i64, align 8
  %"@i_key7" = alloca i64, align 8
  %"@i_val4" = alloca i64, align 8
  %"@i_key3" = alloca i64, align 8
  %lookup_elem_val = alloca i64, align 8
  %"@i_key1" = alloca i64, align 8
  %"@i_val" = alloca i64, align 8
  %"@i_key" = alloca i64, align 8
  %1 = bitcast i64* %"@i_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 0, i64* %"@i_key", align 8
  %2 = bitcast i64* %"@i_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %2)
  store i64 0, i64* %"@i_val", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo, i64* %"@i_key", i64* %"@i_val", i64 0)
  %3 = bitcast i64* %"@i_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %3)
  %4 = bitcast i64* %"@i_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %4)
  %5 = bitcast i64* %"@i_key1" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %5)
  store i64 0, i64* %"@i_key1", align 8
  %pseudo2 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo2, i64* %"@i_key1")
  %6 = bitcast i64* %lookup_elem_val to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %6)
  %map_lookup_cond = icmp ne i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  %cast = bitcast i8* %lookup_elem to i64*
  %7 = load i64, i64* %cast, align 8
  store i64 %7, i64* %lookup_elem_val, align 8
  br label %lookup_merge

lookup_failure:                                   ; preds = %entry
  store i64 0, i64* %lookup_elem_val, align 8
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  %8 = load i64, i64* %lookup_elem_val, align 8
  %9 = bitcast i64* %lookup_elem_val to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %9)
  %10 = bitcast i64* %"@i_key1" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %10)
  %11 = add i64 %8, 1
  %12 = bitcast i64* %"@i_key3" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %12)
  store i64 0, i64* %"@i_key3", align 8
  %13 = bitcast i64* %"@i_val4" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %13)
  store i64 %11, i64* %"@i_val4", align 8
  %pseudo5 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem6 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo5, i64* %"@i_key3", i64* %"@i_val4", i64 0)
  %14 = bitcast i64* %"@i_val4" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %14)
  %15 = bitcast i64* %"@i_key3" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %15)
  %16 = bitcast i64* %"@i_key7" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %16)
  store i64 0, i64* %"@i_key7", align 8
  %pseudo8 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %lookup_elem9 = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo8, i64* %"@i_key7")
  %17 = bitcast i64* %lookup_elem_val13 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %17)
  %map_lookup_cond14 = icmp ne i8* %lookup_elem9, null
  br i1 %map_lookup_cond14, label %lookup_success10, label %lookup_failure11

lookup_success10:                                 ; preds = %lookup_merge
  %cast15 = bitcast i8* %lookup_elem9 to i64*
  %18 = load i64, i64* %cast15, align 8
  store i64 %18, i64* %lookup_elem_val13, align 8
  br label %lookup_merge12

lookup_failure11:                                 ; preds = %lookup_merge
  store i64 0, i64* %lookup_elem_val13, align 8
  br label %lookup_merge12

lookup_merge12:                                   ; preds = %lookup_failure11, %lookup_success10
  %19 = load i64, i64* %lookup_elem_val13, align 8
  %20 = bitcast i64* %lookup_elem_val13 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %20)
  %21 = bitcast i64* %"@i_key7" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %21)
  %22 = add i64 %19, 1
  %23 = bitcast i64* %"@i_key16" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %23)
  store i64 0, i64* %"@i_key16", align 8
  %24 = bitcast i64* %"@i_val17" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %24)
  store i64 %22, i64* %"@i_val17", align 8
  %pseudo18 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem19 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo18, i64* %"@i_key16", i64* %"@i_val17", i64 0)
  %25 = bitcast i64* %"@i_val17" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %25)
  %26 = bitcast i64* %"@i_key16" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %26)
  %27 = bitcast i64* %"@i_key20" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %27)
  store i64 0, i64* %"@i_key20", align 8
  %pseudo21 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %lookup_elem22 = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo21, i64* %"@i_key20")
  %28 = bitcast i64* %lookup_elem_val26 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %28)
  %map_lookup_cond27 = icmp ne i8* %lookup_elem22, null
  br i1 %map_lookup_cond27, label %lookup_success23, label %lookup_failure24

lookup_success23:                                 ; preds = %lookup_merge12
  %cast28 = bitcast i8* %lookup_elem22 to i64*
  %29 = load i64, i64* %cast28, align 8
  store i64 %29, i64* %lookup_elem_val26, align 8
  br label %lookup_merge25

lookup_failure24:                                 ; preds = %lookup_merge12
  store i64 0, i64* %lookup_elem_val26, align 8
  br label %lookup_merge25

lookup_merge25:                                   ; preds = %lookup_failure24, %lookup_success23
  %30 = load i64, i64* %lookup_elem_val26, align 8
  %31 = bitcast i64* %lookup_elem_val26 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %31)
  %32 = bitcast i64* %"@i_key20" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %32)
  %33 = add i64 %30, 1
  %34 = bitcast i64* %"@i_key29" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %34)
  store i64 0, i64* %"@i_key29", align 8
  %35 = bitcast i64* %"@i_val30" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %35)
  store i64 %33, i64* %"@i_val30", align 8
  %pseudo31 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem32 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo31, i64* %"@i_key29", i64* %"@i_val30", i64 0)
  %36 = bitcast i64* %"@i_val30" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %36)
  %37 = bitcast i64* %"@i_key29" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %37)
  %38 = bitcast i64* %"@i_key33" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %38)
  store i64 0, i64* %"@i_key33", align 8
  %pseudo34 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %lookup_elem35 = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo34, i64* %"@i_key33")
  %39 = bitcast i64* %lookup_elem_val39 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %39)
  %map_lookup_cond40 = icmp ne i8* %lookup_elem35, null
  br i1 %map_lookup_cond40, label %lookup_success36, label %lookup_failure37

lookup_success36:                                 ; preds = %lookup_merge25
  %cast41 = bitcast i8* %lookup_elem35 to i64*
  %40 = load i64, i64* %cast41, align 8
  store i64 %40, i64* %lookup_elem_val39, align 8
  br label %lookup_merge38

lookup_failure37:                                 ; preds = %lookup_merge25
  store i64 0, i64* %lookup_elem_val39, align 8
  br label %lookup_merge38

lookup_merge38:                                   ; preds = %lookup_failure37, %lookup_success36
  %41 = load i64, i64* %lookup_elem_val39, align 8
  %42 = bitcast i64* %lookup_elem_val39 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %42)
  %43 = bitcast i64* %"@i_key33" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %43)
  %44 = add i64 %41, 1
  %45 = bitcast i64* %"@i_key42" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %45)
  store i64 0, i64* %"@i_key42", align 8
  %46 = bitcast i64* %"@i_val43" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %46)
  store i64 %44, i64* %"@i_val43", align 8
  %pseudo44 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem45 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo44, i64* %"@i_key42", i64* %"@i_val43", i64 0)
  %47 = bitcast i64* %"@i_val43" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %47)
  %48 = bitcast i64* %"@i_key42" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %48)
  %49 = bitcast i64* %"@i_key46" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %49)
  store i64 0, i64* %"@i_key46", align 8
  %pseudo47 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %lookup_elem48 = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo47, i64* %"@i_key46")
  %50 = bitcast i64* %lookup_elem_val52 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %50)
  %map_lookup_cond53 = icmp ne i8* %lookup_elem48, null
  br i1 %map_lookup_cond53, label %lookup_success49, label %lookup_failure50

lookup_success49:                                 ; preds = %lookup_merge38
  %cast54 = bitcast i8* %lookup_elem48 to i64*
  %51 = load i64, i64* %cast54, align 8
  store i64 %51, i64* %lookup_elem_val52, align 8
  br label %lookup_merge51

lookup_failure50:                                 ; preds = %lookup_merge38
  store i64 0, i64* %lookup_elem_val52, align 8
  br label %lookup_merge51

lookup_merge51:                                   ; preds = %lookup_failure50, %lookup_success49
  %52 = load i64, i64* %lookup_elem_val52, align 8
  %53 = bitcast i64* %lookup_elem_val52 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %53)
  %54 = bitcast i64* %"@i_key46" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %54)
  %55 = add i64 %52, 1
  %56 = bitcast i64* %"@i_key55" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %56)
  store i64 0, i64* %"@i_key55", align 8
  %57 = bitcast i64* %"@i_val56" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %57)
  store i64 %55, i64* %"@i_val56", align 8
  %pseudo57 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem58 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo57, i64* %"@i_key55", i64* %"@i_val56", i64 0)
  %58 = bitcast i64* %"@i_val56" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %58)
  %59 = bitcast i64* %"@i_key55" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %59)
  ret i64 0
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }
