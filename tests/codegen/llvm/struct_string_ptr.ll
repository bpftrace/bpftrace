; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

define i64 @"kprobe:f"(i8*) section "s_kprobe:f_1" {
entry:
  %"@mystr_key" = alloca i64
  %"struct Foo.str" = alloca i64
  %str = alloca [64 x i8]
  %strlen = alloca i64
  %"$foo" = alloca i64
  %1 = bitcast i64* %"$foo" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 0, i64* %"$foo"
  %2 = bitcast i64* %"$foo" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %2)
  store i64 0, i64* %"$foo"
  %3 = bitcast i64* %strlen to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %3)
  %4 = bitcast i64* %strlen to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %4, i8 0, i64 8, i1 false)
  store i64 64, i64* %strlen
  %5 = bitcast [64 x i8]* %str to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %5)
  %6 = bitcast [64 x i8]* %str to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %6, i8 0, i64 64, i1 false)
  %7 = load i64, i64* %"$foo"
  %8 = add i64 %7, 0
  %9 = bitcast i64* %"struct Foo.str" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %9)
  %probe_read_kernel = call i64 inttoptr (i64 113 to i64 (i64*, i32, i64)*)(i64* %"struct Foo.str", i32 8, i64 %8)
  %10 = load i64, i64* %"struct Foo.str"
  %11 = bitcast i64* %"struct Foo.str" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %11)
  %12 = load i64, i64* %strlen
  %13 = trunc i64 %12 to i32
  %probe_read_kernel_str = call i64 inttoptr (i64 115 to i64 ([64 x i8]*, i32, i64)*)([64 x i8]* %str, i32 %13, i64 %10)
  %14 = icmp sgt i64 %probe_read_kernel_str, 0
  br i1 %14, label %str_success, label %str_merge

str_success:                                      ; preds = %entry
  %15 = bitcast [64 x i8]* %str to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %15, i8 0, i64 64, i1 false)
  %16 = and i64 %probe_read_kernel_str, 63
  %17 = trunc i64 %16 to i32
  %probe_read_kernel1 = call i64 inttoptr (i64 113 to i64 ([64 x i8]*, i32, i64)*)([64 x i8]* %str, i32 %17, i64 %10)
  br label %str_merge

str_merge:                                        ; preds = %str_success, %entry
  %18 = bitcast i64* %strlen to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %18)
  %19 = bitcast i64* %"@mystr_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %19)
  store i64 0, i64* %"@mystr_key"
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, [64 x i8]*, i64)*)(i64 %pseudo, i64* %"@mystr_key", [64 x i8]* %str, i64 0)
  %20 = bitcast i64* %"@mystr_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %20)
  %21 = bitcast [64 x i8]* %str to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %21)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i1) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
