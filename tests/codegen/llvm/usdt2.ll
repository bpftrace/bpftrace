; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

define i64 @"usdt:./testprogs/usdt_semaphore_test:tracetest:testprobe_loc0"(i8*) section "s_usdt:./testprogs/usdt_semaphore_test:tracetest:testprobe_loc0_1" {
entry:
  %"$x" = alloca [64 x i8]
  %1 = bitcast [64 x i8]* %"$x" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  %2 = bitcast [64 x i8]* %"$x" to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %2, i8 0, i64 64, i1 false)
  %arg1 = alloca i64
  %str = alloca [64 x i8]
  %strlen = alloca i64
  %3 = bitcast i64* %strlen to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %3)
  %4 = bitcast i64* %strlen to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %4, i8 0, i64 8, i1 false)
  store i64 64, i64* %strlen
  %5 = bitcast [64 x i8]* %str to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %5)
  %6 = bitcast [64 x i8]* %str to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %6, i8 0, i64 64, i1 false)
  %load_register = getelementptr i8, i8* %0, i64 96
  %7 = bitcast i64* %arg1 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %7)
  %8 = bitcast i8* %load_register to i64*
  %9 = load i64, i64* %8
  %10 = bitcast i64* %arg1 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %10)
  %11 = load i64, i64* %strlen
  %12 = trunc i64 %11 to i32
  %probe_read_user_str = call i64 inttoptr (i64 114 to i64 ([64 x i8]*, i32, i64)*)([64 x i8]* %str, i32 %12, i64 %9)
  %13 = bitcast i64* %strlen to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %13)
  %14 = bitcast [64 x i8]* %"$x" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %14)
  %15 = bitcast [64 x i8]* %"$x" to i8*
  %16 = bitcast [64 x i8]* %str to i8*
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* align 1 %15, i8* align 1 %16, i64 64, i1 false)
  %17 = bitcast [64 x i8]* %str to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %17)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64 immarg, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i1 immarg) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64 immarg, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.memcpy.p0i8.p0i8.i64(i8* nocapture writeonly, i8* nocapture readonly, i64, i1 immarg) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
