; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

define i64 @"kprobe:f"(i8*) section "s_kprobe:f_1" {
entry:
  %"@x_key" = alloca i64
  %str = alloca [64 x i8]
  %strlen = alloca i64
  %1 = bitcast i64* %strlen to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  %2 = bitcast i64* %strlen to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %2, i8 0, i64 8, i1 false)
  store i64 64, i64* %strlen
  %3 = bitcast [64 x i8]* %str to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %3)
  %4 = bitcast [64 x i8]* %str to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %4, i8 0, i64 64, i1 false)
  %5 = bitcast i8* %0 to i64*
  %6 = getelementptr i64, i64* %5, i64 14
  %arg0 = load volatile i64, i64* %6
  %7 = load i64, i64* %strlen
  %8 = trunc i64 %7 to i32
  %probe_read_kernel_str = call i64 inttoptr (i64 115 to i64 ([64 x i8]*, i32, i64)*)([64 x i8]* %str, i32 %8, i64 %arg0)
  %9 = icmp sgt i64 %probe_read_kernel_str, 0
  br i1 %9, label %str_success, label %str_merge

str_success:                                      ; preds = %entry
  %10 = bitcast [64 x i8]* %str to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %10, i8 0, i64 64, i1 false)
  %11 = and i64 %probe_read_kernel_str, 63
  %12 = trunc i64 %11 to i32
  %probe_read_kernel = call i64 inttoptr (i64 113 to i64 ([64 x i8]*, i32, i64)*)([64 x i8]* %str, i32 %12, i64 %arg0)
  br label %str_merge

str_merge:                                        ; preds = %str_success, %entry
  %13 = bitcast i64* %strlen to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %13)
  %14 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %14)
  store i64 0, i64* %"@x_key"
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, [64 x i8]*, i64)*)(i64 %pseudo, i64* %"@x_key", [64 x i8]* %str, i64 0)
  %15 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %15)
  %16 = bitcast [64 x i8]* %str to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %16)
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
