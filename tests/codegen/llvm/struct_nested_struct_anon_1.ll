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
  %"struct Foo::(anonymous at definitions.h:1:14).x" = alloca i32
  %"$foo" = alloca [4 x i8]
  %1 = bitcast [4 x i8]* %"$foo" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  %2 = bitcast [4 x i8]* %"$foo" to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %2, i8 0, i64 4, i1 false)
  %3 = bitcast [4 x i8]* %"$foo" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %3)
  %4 = bitcast [4 x i8]* %"$foo" to i8*
  %5 = bitcast i64 0 to i8 addrspace(64)*
  call void @llvm.memcpy.p0i8.p64i8.i64(i8* align 1 %4, i8 addrspace(64)* align 1 %5, i64 4, i1 false)
  %6 = add [4 x i8]* %"$foo", i64 0
  %7 = add [4 x i8]* %6, i64 0
  %8 = bitcast i32* %"struct Foo::(anonymous at definitions.h:1:14).x" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %8)
  %probe_read = call i64 inttoptr (i64 4 to i64 (i32*, i32, [4 x i8]*)*)(i32* %"struct Foo::(anonymous at definitions.h:1:14).x", i32 4, [4 x i8]* %7)
  %9 = load i32, i32* %"struct Foo::(anonymous at definitions.h:1:14).x"
  %10 = sext i32 %9 to i64
  %11 = bitcast i32* %"struct Foo::(anonymous at definitions.h:1:14).x" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %11)
  %12 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %12)
  store i64 0, i64* %"@x_key"
  %13 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %13)
  store i64 %10, i64* %"@x_val"
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo, i64* %"@x_key", i64* %"@x_val", i64 0)
  %14 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %14)
  %15 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %15)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i1) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.memcpy.p0i8.p64i8.i64(i8* nocapture writeonly, i8 addrspace(64)* nocapture readonly, i64, i1) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
