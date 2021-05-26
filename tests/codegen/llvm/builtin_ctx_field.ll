; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"kprobe:f"(i8* %0) section "s_kprobe:f_1" {
entry:
  %"@e_key" = alloca i64, align 8
  %"struct x.e" = alloca [4 x i8], align 1
  %"@d_val" = alloca i64, align 8
  %"@d_key" = alloca i64, align 8
  %"struct c.c" = alloca i8, align 1
  %"@c_val" = alloca i64, align 8
  %"@c_key" = alloca i64, align 8
  %"@b_val" = alloca i64, align 8
  %"@b_key" = alloca i64, align 8
  %"@a_val" = alloca i64, align 8
  %"@a_key" = alloca i64, align 8
  %"$x" = alloca i64, align 8
  %1 = bitcast i64* %"$x" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 0, i64* %"$x", align 8
  %2 = ptrtoint i8* %0 to i64
  store i64 %2, i64* %"$x", align 8
  %3 = load i64, i64* %"$x", align 8
  %4 = add i64 %3, 0
  %5 = inttoptr i64 %4 to i64*
  %6 = load volatile i64, i64* %5, align 8
  %7 = bitcast i64* %"@a_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %7)
  store i64 0, i64* %"@a_key", align 8
  %8 = bitcast i64* %"@a_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %8)
  store i64 %6, i64* %"@a_val", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo, i64* %"@a_key", i64* %"@a_val", i64 0)
  %9 = bitcast i64* %"@a_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %9)
  %10 = bitcast i64* %"@a_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %10)
  %11 = load i64, i64* %"$x", align 8
  %12 = add i64 %11, 8
  %13 = add i64 %12, 0
  %14 = inttoptr i64 %13 to i16*
  %15 = load volatile i16, i16* %14, align 2
  %16 = sext i16 %15 to i64
  %17 = bitcast i64* %"@b_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %17)
  store i64 0, i64* %"@b_key", align 8
  %18 = bitcast i64* %"@b_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %18)
  store i64 %16, i64* %"@b_val", align 8
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem2 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo1, i64* %"@b_key", i64* %"@b_val", i64 0)
  %19 = bitcast i64* %"@b_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %19)
  %20 = bitcast i64* %"@b_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %20)
  %21 = load i64, i64* %"$x", align 8
  %22 = add i64 %21, 16
  %23 = add i64 %22, 0
  %24 = inttoptr i64 %23 to i8*
  %25 = load volatile i8, i8* %24, align 1
  %26 = sext i8 %25 to i64
  %27 = bitcast i64* %"@c_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %27)
  store i64 0, i64* %"@c_key", align 8
  %28 = bitcast i64* %"@c_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %28)
  store i64 %26, i64* %"@c_val", align 8
  %pseudo3 = call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  %update_elem4 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo3, i64* %"@c_key", i64* %"@c_val", i64 0)
  %29 = bitcast i64* %"@c_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %29)
  %30 = bitcast i64* %"@c_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %30)
  %31 = load i64, i64* %"$x", align 8
  %32 = add i64 %31, 24
  %33 = inttoptr i64 %32 to i64*
  %34 = load volatile i64, i64* %33, align 8
  %35 = add i64 %34, 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %"struct c.c")
  %probe_read_kernel = call i64 inttoptr (i64 113 to i64 (i8*, i32, i64)*)(i8* %"struct c.c", i32 1, i64 %35)
  %36 = load i8, i8* %"struct c.c", align 1
  %37 = sext i8 %36 to i64
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %"struct c.c")
  %38 = bitcast i64* %"@d_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %38)
  store i64 0, i64* %"@d_key", align 8
  %39 = bitcast i64* %"@d_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %39)
  store i64 %37, i64* %"@d_val", align 8
  %pseudo5 = call i64 @llvm.bpf.pseudo(i64 1, i64 3)
  %update_elem6 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo5, i64* %"@d_key", i64* %"@d_val", i64 0)
  %40 = bitcast i64* %"@d_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %40)
  %41 = bitcast i64* %"@d_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %41)
  %42 = load i64, i64* %"$x", align 8
  %43 = add i64 %42, 32
  %44 = bitcast [4 x i8]* %"struct x.e" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %44)
  %45 = inttoptr i64 %43 to [4 x i8]*
  %46 = bitcast [4 x i8]* %"struct x.e" to i8*
  %47 = bitcast [4 x i8]* %45 to i8*
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* align 1 %46, i8* align 1 %47, i64 4, i1 true)
  %48 = bitcast i64* %"@e_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %48)
  store i64 0, i64* %"@e_key", align 8
  %pseudo7 = call i64 @llvm.bpf.pseudo(i64 1, i64 4)
  %update_elem8 = call i64 inttoptr (i64 2 to i64 (i64, i64*, [4 x i8]*, i64)*)(i64 %pseudo7, i64* %"@e_key", [4 x i8]* %"struct x.e", i64 0)
  %49 = bitcast i64* %"@e_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %49)
  %50 = bitcast [4 x i8]* %"struct x.e" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %50)
  ret i64 0
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.memcpy.p0i8.p0i8.i64(i8* noalias nocapture writeonly %0, i8* noalias nocapture readonly %1, i64 %2, i1 immarg %3) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }
