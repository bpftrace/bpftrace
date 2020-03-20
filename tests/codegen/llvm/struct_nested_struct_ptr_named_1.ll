; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"kprobe:f"(i8* nocapture readnone) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %"@x_val" = alloca i64, align 8
  %"@x_key" = alloca i64, align 8
  %"struct Bar.x" = alloca i32, align 4
  %"struct Foo.bar" = alloca i64, align 8
  %"$foo" = alloca i64, align 8
  %tmpcast = bitcast i64* %"$foo" to [8 x i8]*
  %1 = bitcast i64* %"$foo" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  store i64 0, i64* %"$foo", align 8
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %2 = load i64, i64 addrspace(64)* null, align 536870912
  store i64 %2, i64* %"$foo", align 8
  %3 = bitcast i64* %"struct Foo.bar" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %3)
  %probe_read = call i64 inttoptr (i64 4 to i64 (i64*, i32, [8 x i8]*)*)(i64* nonnull %"struct Foo.bar", i32 8, [8 x i8]* nonnull %tmpcast)
  %4 = load i64, i64* %"struct Foo.bar", align 8
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %3)
  %5 = bitcast i32* %"struct Bar.x" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %5)
  %probe_read1 = call i64 inttoptr (i64 4 to i64 (i32*, i32, i64)*)(i32* nonnull %"struct Bar.x", i32 4, i64 %4)
  %6 = load i32, i32* %"struct Bar.x", align 4
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %5)
  %7 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %7)
  store i64 0, i64* %"@x_key", align 8
  %8 = sext i32 %6 to i64
  %9 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %9)
  store i64 %8, i64* %"@x_val", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo, i64* nonnull %"@x_key", i64* nonnull %"@x_val", i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %7)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %9)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
