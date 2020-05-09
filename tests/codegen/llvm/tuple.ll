; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

%"int64_int64_string[64]__tuple_t" = type <{ i64, i64, [64 x i8] }>

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

define i64 @"kprobe:f"(i8* nocapture readnone) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %"@t_key" = alloca i64, align 8
  %tuple = alloca %"int64_int64_string[64]__tuple_t", align 8
  %1 = bitcast %"int64_int64_string[64]__tuple_t"* %tuple to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %2 = getelementptr inbounds %"int64_int64_string[64]__tuple_t", %"int64_int64_string[64]__tuple_t"* %tuple, i64 0, i32 0
  store i64 1, i64* %2, align 8
  %3 = getelementptr inbounds %"int64_int64_string[64]__tuple_t", %"int64_int64_string[64]__tuple_t"* %tuple, i64 0, i32 1
  store i64 2, i64* %3, align 8
  %str.sroa.0.0..sroa_idx = getelementptr inbounds %"int64_int64_string[64]__tuple_t", %"int64_int64_string[64]__tuple_t"* %tuple, i64 0, i32 2, i64 0
  store i8 115, i8* %str.sroa.0.0..sroa_idx, align 8
  %str.sroa.4.0..sroa_idx = getelementptr inbounds %"int64_int64_string[64]__tuple_t", %"int64_int64_string[64]__tuple_t"* %tuple, i64 0, i32 2, i64 1
  store i8 116, i8* %str.sroa.4.0..sroa_idx, align 1
  %str.sroa.5.0..sroa_idx = getelementptr inbounds %"int64_int64_string[64]__tuple_t", %"int64_int64_string[64]__tuple_t"* %tuple, i64 0, i32 2, i64 2
  store i8 114, i8* %str.sroa.5.0..sroa_idx, align 2
  %str.sroa.6.0..sroa_idx = getelementptr inbounds %"int64_int64_string[64]__tuple_t", %"int64_int64_string[64]__tuple_t"* %tuple, i64 0, i32 2, i64 3
  %4 = bitcast i64* %"@t_key" to i8*
  call void @llvm.memset.p0i8.i64(i8* nonnull align 1 %str.sroa.6.0..sroa_idx, i8 0, i64 61, i1 false)
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %4)
  store i64 0, i64* %"@t_key", align 8
  %pseudo = tail call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, %"int64_int64_string[64]__tuple_t"*, i64)*)(i64 %pseudo, i64* nonnull %"@t_key", %"int64_int64_string[64]__tuple_t"* nonnull %tuple, i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %4)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
