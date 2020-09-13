; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

define i64 @"kprobe:f"(i8*) section "s_kprobe:f_1" {
entry:
  %"@x_val" = alloca i64
  %"@x_key" = alloca i64
  %"internal_struct Foo.bar13" = alloca [8 x i8]
  %lookup_elem_val11 = alloca [16 x i8]
  %"@foo_key5" = alloca i64
  %"@bar_key" = alloca i64
  %"internal_struct Foo.bar" = alloca [8 x i8]
  %lookup_elem_val = alloca [16 x i8]
  %"@foo_key1" = alloca i64
  %"@foo_val" = alloca [16 x i8]
  %"@foo_key" = alloca i64
  %1 = bitcast i64* %"@foo_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 0, i64* %"@foo_key"
  %2 = bitcast [16 x i8]* %"@foo_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %2)
  %probe_read_kernel = call i64 inttoptr (i64 113 to i64 ([16 x i8]*, i32, i64)*)([16 x i8]* %"@foo_val", i32 16, i64 0)
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, [16 x i8]*, i64)*)(i64 %pseudo, i64* %"@foo_key", [16 x i8]* %"@foo_val", i64 0)
  %3 = bitcast i64* %"@foo_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %3)
  %4 = bitcast [16 x i8]* %"@foo_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %4)
  %5 = bitcast i64* %"@foo_key1" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %5)
  store i64 0, i64* %"@foo_key1"
  %pseudo2 = call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo2, i64* %"@foo_key1")
  %6 = bitcast [16 x i8]* %lookup_elem_val to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %6)
  %map_lookup_cond = icmp ne i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  %7 = bitcast [16 x i8]* %lookup_elem_val to i8*
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* align 1 %7, i8* align 1 %lookup_elem, i64 16, i1 false)
  br label %lookup_merge

lookup_failure:                                   ; preds = %entry
  %8 = bitcast [16 x i8]* %lookup_elem_val to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %8, i8 0, i64 16, i1 false)
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  %9 = bitcast i64* %"@foo_key1" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %9)
  %10 = getelementptr [16 x i8], [16 x i8]* %lookup_elem_val, i64 0, i64 4
  %11 = bitcast [8 x i8]* %"internal_struct Foo.bar" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %11)
  %12 = bitcast [8 x i8]* %"internal_struct Foo.bar" to i8*
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* align 1 %12, i8* align 1 %10, i64 8, i1 false)
  %13 = bitcast [16 x i8]* %lookup_elem_val to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %13)
  %14 = bitcast i64* %"@bar_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %14)
  store i64 0, i64* %"@bar_key"
  %pseudo3 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem4 = call i64 inttoptr (i64 2 to i64 (i64, i64*, [8 x i8]*, i64)*)(i64 %pseudo3, i64* %"@bar_key", [8 x i8]* %"internal_struct Foo.bar", i64 0)
  %15 = bitcast i64* %"@bar_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %15)
  %16 = bitcast [8 x i8]* %"internal_struct Foo.bar" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %16)
  %17 = bitcast i64* %"@foo_key5" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %17)
  store i64 0, i64* %"@foo_key5"
  %pseudo6 = call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  %lookup_elem7 = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo6, i64* %"@foo_key5")
  %18 = bitcast [16 x i8]* %lookup_elem_val11 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %18)
  %map_lookup_cond12 = icmp ne i8* %lookup_elem7, null
  br i1 %map_lookup_cond12, label %lookup_success8, label %lookup_failure9

lookup_success8:                                  ; preds = %lookup_merge
  %19 = bitcast [16 x i8]* %lookup_elem_val11 to i8*
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* align 1 %19, i8* align 1 %lookup_elem7, i64 16, i1 false)
  br label %lookup_merge10

lookup_failure9:                                  ; preds = %lookup_merge
  %20 = bitcast [16 x i8]* %lookup_elem_val11 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %20, i8 0, i64 16, i1 false)
  br label %lookup_merge10

lookup_merge10:                                   ; preds = %lookup_failure9, %lookup_success8
  %21 = bitcast i64* %"@foo_key5" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %21)
  %22 = getelementptr [16 x i8], [16 x i8]* %lookup_elem_val11, i64 0, i64 4
  %23 = bitcast [8 x i8]* %"internal_struct Foo.bar13" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %23)
  %24 = bitcast [8 x i8]* %"internal_struct Foo.bar13" to i8*
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* align 1 %24, i8* align 1 %22, i64 8, i1 false)
  %25 = bitcast [16 x i8]* %lookup_elem_val11 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %25)
  %26 = getelementptr [8 x i8], [8 x i8]* %"internal_struct Foo.bar13", i64 0, i64 0
  %27 = load i32, i8* %26
  %28 = bitcast [8 x i8]* %"internal_struct Foo.bar13" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %28)
  %29 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %29)
  store i64 0, i64* %"@x_key"
  %30 = sext i32 %27 to i64
  %31 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %31)
  store i64 %30, i64* %"@x_val"
  %pseudo14 = call i64 @llvm.bpf.pseudo(i64 1, i64 3)
  %update_elem15 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo14, i64* %"@x_key", i64* %"@x_val", i64 0)
  %32 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %32)
  %33 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %33)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.memcpy.p0i8.p0i8.i64(i8* nocapture writeonly, i8* nocapture readonly, i64, i1) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
