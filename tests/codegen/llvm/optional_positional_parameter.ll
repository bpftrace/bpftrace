; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

define i64 @BEGIN(i8*) section "s_BEGIN_1" {
entry:
  %"@y_key" = alloca i64
  %str1 = alloca [1 x i8]
  %str = alloca [64 x i8]
  %strlen = alloca i64
  %"@x_val" = alloca i64
  %"@x_key" = alloca i64
  %1 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 0, i64* %"@x_key"
  %2 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %2)
  store i64 0, i64* %"@x_val"
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo, i64* %"@x_key", i64* %"@x_val", i64 0)
  %3 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %3)
  %4 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %4)
  %5 = bitcast i64* %strlen to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %5)
  %6 = bitcast i64* %strlen to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %6, i8 0, i64 8, i1 false)
  store i64 64, i64* %strlen
  %7 = bitcast [64 x i8]* %str to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %7)
  %8 = bitcast [64 x i8]* %str to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %8, i8 0, i64 64, i1 false)
  %9 = bitcast [1 x i8]* %str1 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %9)
  %10 = bitcast [1 x i8]* %str1 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %10, i8 0, i64 1, i1 false)
  store [1 x i8] zeroinitializer, [1 x i8]* %str1
  %11 = ptrtoint [1 x i8]* %str1 to i64
  %12 = load i64, i64* %strlen
  %13 = trunc i64 %12 to i32
  %probe_read_kernel_str = call i64 inttoptr (i64 115 to i64 ([64 x i8]*, i32, i64)*)([64 x i8]* %str, i32 %13, i64 %11)
  %14 = icmp sgt i64 %probe_read_kernel_str, 0
  br i1 %14, label %str_success, label %str_merge

str_success:                                      ; preds = %entry
  %15 = bitcast [64 x i8]* %str to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %15, i8 0, i64 64, i1 false)
  %16 = and i64 %probe_read_kernel_str, 63
  %17 = trunc i64 %16 to i32
  %probe_read_kernel = call i64 inttoptr (i64 113 to i64 ([64 x i8]*, i32, i64)*)([64 x i8]* %str, i32 %17, i64 %11)
  br label %str_merge

str_merge:                                        ; preds = %str_success, %entry
  %18 = bitcast i64* %strlen to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %18)
  %19 = bitcast [1 x i8]* %str1 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %19)
  %20 = bitcast i64* %"@y_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %20)
  store i64 0, i64* %"@y_key"
  %pseudo2 = call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  %update_elem3 = call i64 inttoptr (i64 2 to i64 (i64, i64*, [64 x i8]*, i64)*)(i64 %pseudo2, i64* %"@y_key", [64 x i8]* %str, i64 0)
  %21 = bitcast i64* %"@y_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %21)
  %22 = bitcast [64 x i8]* %str to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %22)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
