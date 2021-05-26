; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct Foo_int32[4]__tuple_t" = type { [8 x i8], [4 x i32] }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"kprobe:f"(i8* %0) section "s_kprobe:f_1" {
entry:
  %"@t_key" = alloca i64, align 8
  %tuple = alloca %"struct Foo_int32[4]__tuple_t", align 8
  %1 = bitcast %"struct Foo_int32[4]__tuple_t"* %tuple to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  %2 = bitcast %"struct Foo_int32[4]__tuple_t"* %tuple to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %2, i8 0, i64 24, i1 false)
  %3 = bitcast i8* %0 to i64*
  %4 = getelementptr i64, i64* %3, i64 14
  %arg0 = load volatile i64, i64* %4, align 8
  %5 = getelementptr %"struct Foo_int32[4]__tuple_t", %"struct Foo_int32[4]__tuple_t"* %tuple, i32 0, i32 0
  %probe_read_kernel = call i64 inttoptr (i64 113 to i64 ([8 x i8]*, i32, i64)*)([8 x i8]* %5, i32 8, i64 %arg0)
  %6 = bitcast i8* %0 to i64*
  %7 = getelementptr i64, i64* %6, i64 13
  %arg1 = load volatile i64, i64* %7, align 8
  %8 = add i64 %arg1, 0
  %9 = getelementptr %"struct Foo_int32[4]__tuple_t", %"struct Foo_int32[4]__tuple_t"* %tuple, i32 0, i32 1
  %probe_read_kernel1 = call i64 inttoptr (i64 113 to i64 ([4 x i32]*, i32, i64)*)([4 x i32]* %9, i32 16, i64 %8)
  %10 = bitcast i64* %"@t_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %10)
  store i64 0, i64* %"@t_key", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, %"struct Foo_int32[4]__tuple_t"*, i64)*)(i64 %pseudo, i64* %"@t_key", %"struct Foo_int32[4]__tuple_t"* %tuple, i64 0)
  %11 = bitcast i64* %"@t_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %11)
  %12 = bitcast %"struct Foo_int32[4]__tuple_t"* %tuple to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %12)
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
