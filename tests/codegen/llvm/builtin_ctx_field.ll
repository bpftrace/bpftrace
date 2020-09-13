; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

define i64 @"kprobe:f"(i8*) section "s_kprobe:f_1" {
entry:
  %"@e_key" = alloca i64
  %"struct x.e" = alloca [4 x i8]
  %"@d_val" = alloca i64
  %"@d_key" = alloca i64
  %"struct c.c" = alloca i8
  %"@c_val" = alloca i64
  %"@c_key" = alloca i64
  %"@b_val" = alloca i64
  %"@b_key" = alloca i64
  %"@a_val" = alloca i64
  %"@a_key" = alloca i64
  %"$x" = alloca i64
  %1 = bitcast i64* %"$x" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 0, i64* %"$x"
  %2 = ptrtoint i8* %0 to i64
  %3 = bitcast i64* %"$x" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %3)
  store i64 %2, i64* %"$x"
  %4 = load i64, i64* %"$x"
  %5 = add i64 %4, 0
  %6 = inttoptr i64 %5 to i64*
  %7 = load volatile i64, i64* %6
  %8 = bitcast i64* %"@a_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %8)
  store i64 0, i64* %"@a_key"
  %9 = bitcast i64* %"@a_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %9)
  store i64 %7, i64* %"@a_val"
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo, i64* %"@a_key", i64* %"@a_val", i64 0)
  %10 = bitcast i64* %"@a_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %10)
  %11 = bitcast i64* %"@a_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %11)
  %12 = load i64, i64* %"$x"
  %13 = add i64 %12, 8
  %14 = add i64 %13, 0
  %15 = inttoptr i64 %14 to i16*
  %16 = load volatile i16, i16* %15
  %17 = bitcast i64* %"@b_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %17)
  store i64 0, i64* %"@b_key"
  %18 = sext i16 %16 to i64
  %19 = bitcast i64* %"@b_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %19)
  store i64 %18, i64* %"@b_val"
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  %update_elem2 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo1, i64* %"@b_key", i64* %"@b_val", i64 0)
  %20 = bitcast i64* %"@b_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %20)
  %21 = bitcast i64* %"@b_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %21)
  %22 = load i64, i64* %"$x"
  %23 = add i64 %22, 16
  %24 = add i64 %23, 0
  %25 = inttoptr i64 %24 to i8*
  %26 = load volatile i8, i8* %25
  %27 = sext i8 %26 to i64
  %28 = bitcast i64* %"@c_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %28)
  store i64 0, i64* %"@c_key"
  %29 = bitcast i64* %"@c_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %29)
  store i64 %27, i64* %"@c_val"
  %pseudo3 = call i64 @llvm.bpf.pseudo(i64 1, i64 3)
  %update_elem4 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo3, i64* %"@c_key", i64* %"@c_val", i64 0)
  %30 = bitcast i64* %"@c_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %30)
  %31 = bitcast i64* %"@c_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %31)
  %32 = load i64, i64* %"$x"
  %33 = add i64 %32, 24
  %34 = inttoptr i64 %33 to i64*
  %35 = load volatile i64, i64* %34
  %36 = add i64 %35, 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %"struct c.c")
  %probe_read_kernel = call i64 inttoptr (i64 113 to i64 (i8*, i32, i64)*)(i8* %"struct c.c", i32 1, i64 %36)
  %37 = load i8, i8* %"struct c.c"
  %38 = sext i8 %37 to i64
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %"struct c.c")
  %39 = bitcast i64* %"@d_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %39)
  store i64 0, i64* %"@d_key"
  %40 = bitcast i64* %"@d_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %40)
  store i64 %38, i64* %"@d_val"
  %pseudo5 = call i64 @llvm.bpf.pseudo(i64 1, i64 4)
  %update_elem6 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo5, i64* %"@d_key", i64* %"@d_val", i64 0)
  %41 = bitcast i64* %"@d_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %41)
  %42 = bitcast i64* %"@d_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %42)
  %43 = load i64, i64* %"$x"
  %44 = add i64 %43, 32
  %45 = bitcast [4 x i8]* %"struct x.e" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %45)
  %46 = inttoptr i64 %44 to [4 x i8]*
  %47 = bitcast [4 x i8]* %"struct x.e" to i8*
  %48 = bitcast [4 x i8]* %46 to i8*
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* align 1 %47, i8* align 1 %48, i64 4, i1 true)
  %49 = bitcast i64* %"@e_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %49)
  store i64 0, i64* %"@e_key"
  %pseudo7 = call i64 @llvm.bpf.pseudo(i64 1, i64 5)
  %update_elem8 = call i64 inttoptr (i64 2 to i64 (i64, i64*, [4 x i8]*, i64)*)(i64 %pseudo7, i64* %"@e_key", [4 x i8]* %"struct x.e", i64 0)
  %50 = bitcast i64* %"@e_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %50)
  %51 = bitcast [4 x i8]* %"struct x.e" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %51)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.memcpy.p0i8.p0i8.i64(i8* nocapture writeonly, i8* nocapture readonly, i64, i1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
