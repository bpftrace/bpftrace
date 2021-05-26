; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%buffer_1_t = type { i8, [1 x i8] }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"kprobe:f"(i8* %0) section "s_kprobe:f_1" {
entry:
  %"@x_key" = alloca i64, align 8
  %buffer = alloca %buffer_1_t, align 8
  %1 = bitcast %buffer_1_t* %buffer to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  %2 = getelementptr %buffer_1_t, %buffer_1_t* %buffer, i32 0, i32 0
  store i8 1, i8* %2, align 1
  %3 = getelementptr %buffer_1_t, %buffer_1_t* %buffer, i32 0, i32 1
  %4 = bitcast [1 x i8]* %3 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %4, i8 0, i64 1, i1 false)
  %5 = bitcast i8* %0 to i64*
  %6 = getelementptr i64, i64* %5, i64 14
  %arg0 = load volatile i64, i64* %6, align 8
  %probe_read_kernel = call i64 inttoptr (i64 113 to i64 ([1 x i8]*, i32, i64)*)([1 x i8]* %3, i32 1, i64 %arg0)
  %7 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %7)
  store i64 0, i64* %"@x_key", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, %buffer_1_t*, i64)*)(i64 %pseudo, i64* %"@x_key", %buffer_1_t* %buffer, i64 0)
  %8 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %8)
  %9 = bitcast %buffer_1_t* %buffer to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %9)
  ret i64 0
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn writeonly
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }
attributes #2 = { argmemonly nofree nosync nounwind willreturn writeonly }
