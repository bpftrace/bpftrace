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
  %"@x_key" = alloca i64, align 8
  %str = alloca [64 x i8], align 1
  %1 = getelementptr i8, i8* %0, i64 104
  %2 = bitcast i8* %1 to i64*
  %arg1 = load volatile i64, i64* %2, align 8
  %3 = add i64 %arg1, 1
  %4 = icmp ult i64 %3, 64
  %str.min.select = select i1 %4, i64 %3, i64 64
  %5 = getelementptr inbounds [64 x i8], [64 x i8]* %str, i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %5)
  call void @llvm.memset.p0i8.i64(i8* nonnull %5, i8 0, i64 64, i32 1, i1 false)
  %6 = getelementptr i8, i8* %0, i64 112
  %7 = bitcast i8* %6 to i64*
  %arg0 = load volatile i64, i64* %7, align 8
  %8 = trunc i64 %str.min.select to i32
  %probe_read_str = call i64 inttoptr (i64 45 to i64 ([64 x i8]*, i32, i64)*)([64 x i8]* nonnull %str, i32 %8, i64 %arg0)
  %9 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %9)
  store i64 0, i64* %"@x_key", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, [64 x i8]*, i64)*)(i64 %pseudo, i64* nonnull %"@x_key", [64 x i8]* nonnull %str, i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %9)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %5)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i32, i1) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
