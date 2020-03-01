; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"kprobe:f"(i8*) local_unnamed_addr section "s_kprobe:f_1" {
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
  %1 = ptrtoint i8* %0 to i64
  %2 = bitcast i8* %0 to i64*
  %3 = load volatile i64, i64* %2, align 8
  %4 = bitcast i64* %"@a_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %4)
  store i64 0, i64* %"@a_key", align 8
  %5 = bitcast i64* %"@a_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %5)
  store i64 %3, i64* %"@a_val", align 8
  %pseudo = tail call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo, i64* nonnull %"@a_key", i64* nonnull %"@a_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %4)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %5)
  %6 = add i64 %1, 8
  %7 = inttoptr i64 %6 to i16*
  %8 = load volatile i16, i16* %7, align 2
  %9 = bitcast i64* %"@b_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %9)
  store i64 0, i64* %"@b_key", align 8
  %10 = sext i16 %8 to i64
  %11 = bitcast i64* %"@b_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %11)
  store i64 %10, i64* %"@b_val", align 8
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  %update_elem2 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo1, i64* nonnull %"@b_key", i64* nonnull %"@b_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %9)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %11)
  %12 = add i64 %1, 16
  %13 = inttoptr i64 %12 to i8*
  %14 = load volatile i8, i8* %13, align 1
  %15 = bitcast i64* %"@c_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %15)
  store i64 0, i64* %"@c_key", align 8
  %16 = sext i8 %14 to i64
  %17 = bitcast i64* %"@c_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %17)
  store i64 %16, i64* %"@c_val", align 8
  %pseudo3 = call i64 @llvm.bpf.pseudo(i64 1, i64 3)
  %update_elem4 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo3, i64* nonnull %"@c_key", i64* nonnull %"@c_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %15)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %17)
  %18 = add i64 %1, 24
  %19 = inttoptr i64 %18 to i64*
  %20 = load volatile i64, i64* %19, align 8
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %"struct c.c")
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i32, i64)*)(i8* nonnull %"struct c.c", i32 1, i64 %20)
  %21 = load i8, i8* %"struct c.c", align 1
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %"struct c.c")
  %22 = bitcast i64* %"@d_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %22)
  store i64 0, i64* %"@d_key", align 8
  %23 = sext i8 %21 to i64
  %24 = bitcast i64* %"@d_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %24)
  store i64 %23, i64* %"@d_val", align 8
  %pseudo5 = call i64 @llvm.bpf.pseudo(i64 1, i64 4)
  %update_elem6 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo5, i64* nonnull %"@d_key", i64* nonnull %"@d_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %22)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %24)
  %25 = add i64 %1, 32
  %26 = getelementptr inbounds [4 x i8], [4 x i8]* %"struct x.e", i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %26)
  %27 = inttoptr i64 %25 to [4 x i8]*
  %28 = getelementptr inbounds [4 x i8], [4 x i8]* %27, i64 0, i64 0
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* nonnull align 1 %26, i8* align 1 %28, i64 4, i1 true)
  %29 = bitcast i64* %"@e_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %29)
  store i64 0, i64* %"@e_key", align 8
  %pseudo7 = call i64 @llvm.bpf.pseudo(i64 1, i64 5)
  %update_elem8 = call i64 inttoptr (i64 2 to i64 (i64, i64*, [4 x i8]*, i64)*)(i64 %pseudo7, i64* nonnull %"@e_key", [4 x i8]* nonnull %"struct x.e", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %29)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %26)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.memcpy.p0i8.p0i8.i64(i8* nocapture writeonly, i8* nocapture readonly, i64, i1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
