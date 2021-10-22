; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"kprobe:f"(i8* %0) section "s_kprobe:f_1" {
entry:
  %"@x_val" = alloca i64, align 8
  %str1 = alloca [2 x i8], align 1
  %str = alloca [2 x i8], align 1
  %"@x_key" = alloca [4 x i8], align 1
  %1 = bitcast [4 x i8]* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  %2 = bitcast [2 x i8]* %str to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %2)
  store [2 x i8] c"a\00", [2 x i8]* %str, align 1
  %3 = getelementptr [4 x i8], [4 x i8]* %"@x_key", i64 0, i64 0
  %4 = bitcast [2 x i8]* %str to i8*
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* align 1 %3, i8* align 1 %4, i64 2, i1 false)
  %5 = bitcast [2 x i8]* %str to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %5)
  %6 = bitcast [2 x i8]* %str1 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %6)
  store [2 x i8] c"b\00", [2 x i8]* %str1, align 1
  %7 = getelementptr [4 x i8], [4 x i8]* %"@x_key", i64 0, i64 2
  %8 = bitcast [2 x i8]* %str1 to i8*
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* align 1 %7, i8* align 1 %8, i64 2, i1 false)
  %9 = bitcast [2 x i8]* %str1 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %9)
  %10 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %10)
  store i64 44, i64* %"@x_val", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, [4 x i8]*, i64*, i64)*)(i64 %pseudo, [4 x i8]* %"@x_key", i64* %"@x_val", i64 0)
  %11 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %11)
  %12 = bitcast [4 x i8]* %"@x_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %12)
  ret i64 0
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.memcpy.p0i8.p0i8.i64(i8* noalias nocapture writeonly %0, i8* noalias nocapture readonly %1, i64 %2, i1 immarg %3) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }
