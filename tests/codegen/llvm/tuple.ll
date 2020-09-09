; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

%"int64_int64_string[64]__tuple_t" = type { i64, i64, [64 x i8] }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

define i64 @"kprobe:f"(i8*) section "s_kprobe:f_1" {
entry:
  %"@t_key" = alloca i64
  %str = alloca [64 x i8]
  %tuple = alloca %"int64_int64_string[64]__tuple_t"
  %1 = bitcast %"int64_int64_string[64]__tuple_t"* %tuple to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  %2 = bitcast %"int64_int64_string[64]__tuple_t"* %tuple to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %2, i8 0, i64 80, i1 false)
  %3 = getelementptr %"int64_int64_string[64]__tuple_t", %"int64_int64_string[64]__tuple_t"* %tuple, i32 0, i32 0
  store i64 1, i64* %3
  %4 = getelementptr %"int64_int64_string[64]__tuple_t", %"int64_int64_string[64]__tuple_t"* %tuple, i32 0, i32 1
  store i64 2, i64* %4
  %5 = bitcast [64 x i8]* %str to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %5)
  store [64 x i8] c"str\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00", [64 x i8]* %str
  %6 = getelementptr %"int64_int64_string[64]__tuple_t", %"int64_int64_string[64]__tuple_t"* %tuple, i32 0, i32 2
  %7 = bitcast [64 x i8]* %6 to i8*
  %8 = bitcast [64 x i8]* %str to i8*
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* align 1 %7, i8* align 1 %8, i64 64, i1 false)
  %9 = bitcast [64 x i8]* %str to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %9)
  %10 = bitcast i64* %"@t_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %10)
  store i64 0, i64* %"@t_key"
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, %"int64_int64_string[64]__tuple_t"*, i64)*)(i64 %pseudo, i64* %"@t_key", %"int64_int64_string[64]__tuple_t"* %tuple, i64 0)
  %11 = bitcast i64* %"@t_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %11)
  %12 = bitcast %"int64_int64_string[64]__tuple_t"* %tuple to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %12)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i1) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.memcpy.p0i8.p0i8.i64(i8* nocapture writeonly, i8* nocapture readonly, i64, i1) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
