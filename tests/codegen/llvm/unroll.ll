; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

define i64 @BEGIN(i8*) section "s_BEGIN_1" {
entry:
  %"@i_val56" = alloca i64
  %"@i_key55" = alloca i64
  %lookup_elem_val52 = alloca i64
  %"@i_key46" = alloca i64
  %"@i_val43" = alloca i64
  %"@i_key42" = alloca i64
  %lookup_elem_val39 = alloca i64
  %"@i_key33" = alloca i64
  %"@i_val30" = alloca i64
  %"@i_key29" = alloca i64
  %lookup_elem_val26 = alloca i64
  %"@i_key20" = alloca i64
  %"@i_val17" = alloca i64
  %"@i_key16" = alloca i64
  %lookup_elem_val13 = alloca i64
  %"@i_key7" = alloca i64
  %"@i_val4" = alloca i64
  %"@i_key3" = alloca i64
  %lookup_elem_val = alloca i64
  %"@i_key1" = alloca i64
  %"@i_val" = alloca i64
  %"@i_key" = alloca i64
  %1 = bitcast i64* %"@i_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 0, i64* %"@i_key"
  %2 = bitcast i64* %"@i_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %2)
  store i64 0, i64* %"@i_val"
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo, i64* %"@i_key", i64* %"@i_val", i64 0)
  %3 = bitcast i64* %"@i_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %3)
  %4 = bitcast i64* %"@i_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %4)
  %5 = bitcast i64* %"@i_key1" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %5)
  store i64 0, i64* %"@i_key1"
  %pseudo2 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo2, i64* %"@i_key1")
  %6 = bitcast i64* %lookup_elem_val to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %6)
  %map_lookup_cond = icmp ne i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  %cast = bitcast i8* %lookup_elem to i64*
  %7 = load i64, i64* %cast
  store i64 %7, i64* %lookup_elem_val
  br label %lookup_merge

lookup_failure:                                   ; preds = %entry
  store i64 0, i64* %lookup_elem_val
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  %8 = load i64, i64* %lookup_elem_val
  %9 = bitcast i64* %"@i_key1" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %9)
  %10 = add i64 %8, 1
  %11 = bitcast i64* %"@i_key3" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %11)
  store i64 0, i64* %"@i_key3"
  %12 = bitcast i64* %"@i_val4" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %12)
  store i64 %10, i64* %"@i_val4"
  %pseudo5 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem6 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo5, i64* %"@i_key3", i64* %"@i_val4", i64 0)
  %13 = bitcast i64* %"@i_key3" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %13)
  %14 = bitcast i64* %"@i_val4" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %14)
  %15 = bitcast i64* %"@i_key7" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %15)
  store i64 0, i64* %"@i_key7"
  %pseudo8 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem9 = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo8, i64* %"@i_key7")
  %16 = bitcast i64* %lookup_elem_val13 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %16)
  %map_lookup_cond14 = icmp ne i8* %lookup_elem9, null
  br i1 %map_lookup_cond14, label %lookup_success10, label %lookup_failure11

lookup_success10:                                 ; preds = %lookup_merge
  %cast15 = bitcast i8* %lookup_elem9 to i64*
  %17 = load i64, i64* %cast15
  store i64 %17, i64* %lookup_elem_val13
  br label %lookup_merge12

lookup_failure11:                                 ; preds = %lookup_merge
  store i64 0, i64* %lookup_elem_val13
  br label %lookup_merge12

lookup_merge12:                                   ; preds = %lookup_failure11, %lookup_success10
  %18 = load i64, i64* %lookup_elem_val13
  %19 = bitcast i64* %"@i_key7" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %19)
  %20 = add i64 %18, 1
  %21 = bitcast i64* %"@i_key16" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %21)
  store i64 0, i64* %"@i_key16"
  %22 = bitcast i64* %"@i_val17" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %22)
  store i64 %20, i64* %"@i_val17"
  %pseudo18 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem19 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo18, i64* %"@i_key16", i64* %"@i_val17", i64 0)
  %23 = bitcast i64* %"@i_key16" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %23)
  %24 = bitcast i64* %"@i_val17" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %24)
  %25 = bitcast i64* %"@i_key20" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %25)
  store i64 0, i64* %"@i_key20"
  %pseudo21 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem22 = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo21, i64* %"@i_key20")
  %26 = bitcast i64* %lookup_elem_val26 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %26)
  %map_lookup_cond27 = icmp ne i8* %lookup_elem22, null
  br i1 %map_lookup_cond27, label %lookup_success23, label %lookup_failure24

lookup_success23:                                 ; preds = %lookup_merge12
  %cast28 = bitcast i8* %lookup_elem22 to i64*
  %27 = load i64, i64* %cast28
  store i64 %27, i64* %lookup_elem_val26
  br label %lookup_merge25

lookup_failure24:                                 ; preds = %lookup_merge12
  store i64 0, i64* %lookup_elem_val26
  br label %lookup_merge25

lookup_merge25:                                   ; preds = %lookup_failure24, %lookup_success23
  %28 = load i64, i64* %lookup_elem_val26
  %29 = bitcast i64* %"@i_key20" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %29)
  %30 = add i64 %28, 1
  %31 = bitcast i64* %"@i_key29" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %31)
  store i64 0, i64* %"@i_key29"
  %32 = bitcast i64* %"@i_val30" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %32)
  store i64 %30, i64* %"@i_val30"
  %pseudo31 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem32 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo31, i64* %"@i_key29", i64* %"@i_val30", i64 0)
  %33 = bitcast i64* %"@i_key29" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %33)
  %34 = bitcast i64* %"@i_val30" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %34)
  %35 = bitcast i64* %"@i_key33" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %35)
  store i64 0, i64* %"@i_key33"
  %pseudo34 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem35 = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo34, i64* %"@i_key33")
  %36 = bitcast i64* %lookup_elem_val39 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %36)
  %map_lookup_cond40 = icmp ne i8* %lookup_elem35, null
  br i1 %map_lookup_cond40, label %lookup_success36, label %lookup_failure37

lookup_success36:                                 ; preds = %lookup_merge25
  %cast41 = bitcast i8* %lookup_elem35 to i64*
  %37 = load i64, i64* %cast41
  store i64 %37, i64* %lookup_elem_val39
  br label %lookup_merge38

lookup_failure37:                                 ; preds = %lookup_merge25
  store i64 0, i64* %lookup_elem_val39
  br label %lookup_merge38

lookup_merge38:                                   ; preds = %lookup_failure37, %lookup_success36
  %38 = load i64, i64* %lookup_elem_val39
  %39 = bitcast i64* %"@i_key33" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %39)
  %40 = add i64 %38, 1
  %41 = bitcast i64* %"@i_key42" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %41)
  store i64 0, i64* %"@i_key42"
  %42 = bitcast i64* %"@i_val43" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %42)
  store i64 %40, i64* %"@i_val43"
  %pseudo44 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem45 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo44, i64* %"@i_key42", i64* %"@i_val43", i64 0)
  %43 = bitcast i64* %"@i_key42" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %43)
  %44 = bitcast i64* %"@i_val43" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %44)
  %45 = bitcast i64* %"@i_key46" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %45)
  store i64 0, i64* %"@i_key46"
  %pseudo47 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem48 = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo47, i64* %"@i_key46")
  %46 = bitcast i64* %lookup_elem_val52 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %46)
  %map_lookup_cond53 = icmp ne i8* %lookup_elem48, null
  br i1 %map_lookup_cond53, label %lookup_success49, label %lookup_failure50

lookup_success49:                                 ; preds = %lookup_merge38
  %cast54 = bitcast i8* %lookup_elem48 to i64*
  %47 = load i64, i64* %cast54
  store i64 %47, i64* %lookup_elem_val52
  br label %lookup_merge51

lookup_failure50:                                 ; preds = %lookup_merge38
  store i64 0, i64* %lookup_elem_val52
  br label %lookup_merge51

lookup_merge51:                                   ; preds = %lookup_failure50, %lookup_success49
  %48 = load i64, i64* %lookup_elem_val52
  %49 = bitcast i64* %"@i_key46" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %49)
  %50 = add i64 %48, 1
  %51 = bitcast i64* %"@i_key55" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %51)
  store i64 0, i64* %"@i_key55"
  %52 = bitcast i64* %"@i_val56" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %52)
  store i64 %50, i64* %"@i_val56"
  %pseudo57 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem58 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo57, i64* %"@i_key55", i64* %"@i_val56", i64 0)
  %53 = bitcast i64* %"@i_key55" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %53)
  %54 = bitcast i64* %"@i_val56" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %54)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
