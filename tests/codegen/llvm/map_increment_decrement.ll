; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

define i64 @BEGIN(i8*) section "s_BEGIN_1" {
entry:
  %"@x_newval38" = alloca i64
  %lookup_elem_val35 = alloca i64
  %"@x_key29" = alloca i64
  %"@x_newval26" = alloca i64
  %lookup_elem_val23 = alloca i64
  %"@x_key17" = alloca i64
  %"@x_newval14" = alloca i64
  %lookup_elem_val11 = alloca i64
  %"@x_key5" = alloca i64
  %"@x_newval" = alloca i64
  %lookup_elem_val = alloca i64
  %"@x_key1" = alloca i64
  %"@x_val" = alloca i64
  %"@x_key" = alloca i64
  %1 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 0, i64* %"@x_key"
  %2 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %2)
  store i64 10, i64* %"@x_val"
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo, i64* %"@x_key", i64* %"@x_val", i64 0)
  %3 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %3)
  %4 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %4)
  %5 = bitcast i64* %"@x_key1" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %5)
  store i64 0, i64* %"@x_key1"
  %pseudo2 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo2, i64* %"@x_key1")
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
  %9 = bitcast i64* %"@x_newval" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %9)
  %10 = add i64 %8, 1
  store i64 %10, i64* %"@x_newval"
  %pseudo3 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem4 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo3, i64* %"@x_key1", i64* %"@x_newval", i64 0)
  %11 = bitcast i64* %"@x_key1" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %11)
  %12 = bitcast i64* %"@x_newval" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %12)
  %13 = bitcast i64* %"@x_key5" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %13)
  store i64 0, i64* %"@x_key5"
  %pseudo6 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem7 = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo6, i64* %"@x_key5")
  %14 = bitcast i64* %lookup_elem_val11 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %14)
  %map_lookup_cond12 = icmp ne i8* %lookup_elem7, null
  br i1 %map_lookup_cond12, label %lookup_success8, label %lookup_failure9

lookup_success8:                                  ; preds = %lookup_merge
  %cast13 = bitcast i8* %lookup_elem7 to i64*
  %15 = load i64, i64* %cast13
  store i64 %15, i64* %lookup_elem_val11
  br label %lookup_merge10

lookup_failure9:                                  ; preds = %lookup_merge
  store i64 0, i64* %lookup_elem_val11
  br label %lookup_merge10

lookup_merge10:                                   ; preds = %lookup_failure9, %lookup_success8
  %16 = load i64, i64* %lookup_elem_val11
  %17 = bitcast i64* %"@x_newval14" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %17)
  %18 = add i64 %16, 1
  store i64 %18, i64* %"@x_newval14"
  %pseudo15 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem16 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo15, i64* %"@x_key5", i64* %"@x_newval14", i64 0)
  %19 = bitcast i64* %"@x_key5" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %19)
  %20 = load i64, i64* %"@x_newval14"
  %21 = bitcast i64* %"@x_newval14" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %21)
  %22 = bitcast i64* %"@x_key17" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %22)
  store i64 0, i64* %"@x_key17"
  %pseudo18 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem19 = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo18, i64* %"@x_key17")
  %23 = bitcast i64* %lookup_elem_val23 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %23)
  %map_lookup_cond24 = icmp ne i8* %lookup_elem19, null
  br i1 %map_lookup_cond24, label %lookup_success20, label %lookup_failure21

lookup_success20:                                 ; preds = %lookup_merge10
  %cast25 = bitcast i8* %lookup_elem19 to i64*
  %24 = load i64, i64* %cast25
  store i64 %24, i64* %lookup_elem_val23
  br label %lookup_merge22

lookup_failure21:                                 ; preds = %lookup_merge10
  store i64 0, i64* %lookup_elem_val23
  br label %lookup_merge22

lookup_merge22:                                   ; preds = %lookup_failure21, %lookup_success20
  %25 = load i64, i64* %lookup_elem_val23
  %26 = bitcast i64* %"@x_newval26" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %26)
  %27 = sub i64 %25, 1
  store i64 %27, i64* %"@x_newval26"
  %pseudo27 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem28 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo27, i64* %"@x_key17", i64* %"@x_newval26", i64 0)
  %28 = bitcast i64* %"@x_key17" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %28)
  %29 = bitcast i64* %"@x_newval26" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %29)
  %30 = bitcast i64* %"@x_key29" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %30)
  store i64 0, i64* %"@x_key29"
  %pseudo30 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem31 = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo30, i64* %"@x_key29")
  %31 = bitcast i64* %lookup_elem_val35 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %31)
  %map_lookup_cond36 = icmp ne i8* %lookup_elem31, null
  br i1 %map_lookup_cond36, label %lookup_success32, label %lookup_failure33

lookup_success32:                                 ; preds = %lookup_merge22
  %cast37 = bitcast i8* %lookup_elem31 to i64*
  %32 = load i64, i64* %cast37
  store i64 %32, i64* %lookup_elem_val35
  br label %lookup_merge34

lookup_failure33:                                 ; preds = %lookup_merge22
  store i64 0, i64* %lookup_elem_val35
  br label %lookup_merge34

lookup_merge34:                                   ; preds = %lookup_failure33, %lookup_success32
  %33 = load i64, i64* %lookup_elem_val35
  %34 = bitcast i64* %"@x_newval38" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %34)
  %35 = sub i64 %33, 1
  store i64 %35, i64* %"@x_newval38"
  %pseudo39 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem40 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo39, i64* %"@x_key29", i64* %"@x_newval38", i64 0)
  %36 = bitcast i64* %"@x_key29" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %36)
  %37 = load i64, i64* %"@x_newval38"
  %38 = bitcast i64* %"@x_newval38" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %38)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
