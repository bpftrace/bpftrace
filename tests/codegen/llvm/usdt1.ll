; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

define i64 @"usdt:./testprogs/usdt_sized_args:test:probe2_loc0"(i8*) section "s_usdt:./testprogs/usdt_sized_args:test:probe2_loc0_1" {
entry:
  %"$x" = alloca i64
  %1 = bitcast i64* %"$x" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 0, i64* %"$x"
  %arg0 = alloca i32
  %load_register = getelementptr i8, i8* %0, i64 32
  %2 = bitcast i32* %arg0 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %2)
  %3 = bitcast i8* %load_register to i64*
  %4 = load i64, i64* %3
  %5 = add i64 %4, -8
  %probe_read_user = call i64 inttoptr (i64 112 to i64 (i32*, i32, i64)*)(i32* %arg0, i32 4, i64 %5)
  %6 = load i32, i32* %arg0
  %7 = zext i32 %6 to i64
  %8 = bitcast i32* %arg0 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %8)
  %9 = bitcast i64* %"$x" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %9)
  store i64 %7, i64* %"$x"
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64 immarg, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64 immarg, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
