; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"kprobe:f"(i8* %0) section "s_kprobe:f_1" {
entry:
  %"@_val" = alloca i64, align 8
  %"@_key" = alloca i64, align 8
  %addr4 = alloca [4 x i8], align 1
  %1 = bitcast [4 x i8]* %addr4 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  %2 = getelementptr [4 x i8], [4 x i8]* %addr4, i64 0, i64 0
  store i8 127, i8* %2, align 1
  %3 = getelementptr [4 x i8], [4 x i8]* %addr4, i64 0, i64 1
  store i8 0, i8* %3, align 1
  %4 = getelementptr [4 x i8], [4 x i8]* %addr4, i64 0, i64 2
  store i8 0, i8* %4, align 1
  %5 = getelementptr [4 x i8], [4 x i8]* %addr4, i64 0, i64 3
  store i8 1, i8* %5, align 1
  %6 = bitcast [4 x i8]* %addr4 to i32*
  %7 = load volatile i32, i32* %6, align 4
  %8 = bitcast [4 x i8]* %addr4 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %8)
  %9 = bitcast i64* %"@_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %9)
  store i64 0, i64* %"@_key", align 8
  %10 = zext i32 %7 to i64
  %11 = bitcast i64* %"@_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %11)
  store i64 %10, i64* %"@_val", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo, i64* %"@_key", i64* %"@_val", i64 0)
  %12 = bitcast i64* %"@_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %12)
  %13 = bitcast i64* %"@_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %13)
  ret i64 0
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }
