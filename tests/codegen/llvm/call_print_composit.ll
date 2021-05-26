; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%print_tuple_72_t = type <{ i64, i64, [72 x i8] }>
%"int64_string[64]__tuple_t" = type { i64, [64 x i8] }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"kprobe:f"(i8* %0) section "s_kprobe:f_1" {
entry:
  %print_tuple_72_t = alloca %print_tuple_72_t, align 8
  %str = alloca [64 x i8], align 1
  %tuple = alloca %"int64_string[64]__tuple_t", align 8
  %1 = bitcast %"int64_string[64]__tuple_t"* %tuple to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  %2 = bitcast %"int64_string[64]__tuple_t"* %tuple to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %2, i8 0, i64 72, i1 false)
  %3 = getelementptr %"int64_string[64]__tuple_t", %"int64_string[64]__tuple_t"* %tuple, i32 0, i32 0
  store i64 1, i64* %3, align 8
  %4 = bitcast [64 x i8]* %str to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %4)
  store [64 x i8] c"abc\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00", [64 x i8]* %str, align 1
  %5 = getelementptr %"int64_string[64]__tuple_t", %"int64_string[64]__tuple_t"* %tuple, i32 0, i32 1
  %6 = bitcast [64 x i8]* %5 to i8*
  %7 = bitcast [64 x i8]* %str to i8*
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* align 1 %6, i8* align 1 %7, i64 64, i1 false)
  %8 = bitcast [64 x i8]* %str to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %8)
  %9 = bitcast %print_tuple_72_t* %print_tuple_72_t to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %9)
  %10 = getelementptr %print_tuple_72_t, %print_tuple_72_t* %print_tuple_72_t, i64 0, i32 0
  store i64 30007, i64* %10, align 8
  %11 = getelementptr %print_tuple_72_t, %print_tuple_72_t* %print_tuple_72_t, i64 0, i32 1
  store i64 0, i64* %11, align 8
  %12 = getelementptr %print_tuple_72_t, %print_tuple_72_t* %print_tuple_72_t, i32 0, i32 2
  %13 = bitcast [72 x i8]* %12 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %13, i8 0, i64 72, i1 false)
  %14 = bitcast [72 x i8]* %12 to i8*
  %15 = bitcast %"int64_string[64]__tuple_t"* %tuple to i8*
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* align 1 %14, i8* align 1 %15, i64 72, i1 false)
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %print_tuple_72_t*, i64)*)(i8* %0, i64 %pseudo, i64 4294967295, %print_tuple_72_t* %print_tuple_72_t, i64 88)
  %16 = bitcast %print_tuple_72_t* %print_tuple_72_t to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %16)
  %17 = bitcast %"int64_string[64]__tuple_t"* %tuple to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %17)
  ret i64 0
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn writeonly
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.memcpy.p0i8.p0i8.i64(i8* noalias nocapture writeonly %0, i8* noalias nocapture readonly %1, i64 %2, i1 immarg %3) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }
attributes #2 = { argmemonly nofree nosync nounwind willreturn writeonly }
