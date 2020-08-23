; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

%helper_error_t = type <{ i64, i64, i32, i8 }>
%buffer_64_t = type { i32, [64 x i8] }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

define i64 @"kprobe:f"(i8*) section "s_kprobe:f_1" {
entry:
  %"@x_key" = alloca i64
  %helper_error_t = alloca %helper_error_t
  %lookup_buf_key = alloca i32
  %1 = bitcast i8* %0 to i64*
  %2 = getelementptr i64, i64* %1, i64 13
  %arg1 = load volatile i64, i64* %2
  %length.cmp = icmp ule i64 %arg1, 64
  %length.select = select i1 %length.cmp, i64 %arg1, i64 64
  %3 = bitcast i32* %lookup_buf_key to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %3)
  store i32 0, i32* %lookup_buf_key
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 3)
  %lookup_buf_map = call %buffer_64_t* inttoptr (i64 1 to %buffer_64_t* (i64, i32*)*)(i64 %pseudo, i32* %lookup_buf_key)
  %4 = bitcast i32* %lookup_buf_key to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %4)
  %5 = sext %buffer_64_t* %lookup_buf_map to i32
  %6 = icmp ne i32 %5, 0
  br i1 %6, label %helper_merge, label %helper_failure

helper_failure:                                   ; preds = %entry
  %7 = bitcast %helper_error_t* %helper_error_t to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %7)
  %8 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 0
  store i64 30006, i64* %8
  %9 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 1
  store i64 0, i64* %9
  %10 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 2
  store i32 %5, i32* %10
  %11 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 3
  store i8 1, i8* %11
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %helper_error_t*, i64)*)(i8* %0, i64 %pseudo1, i64 4294967295, %helper_error_t* %helper_error_t, i64 21)
  %12 = bitcast %helper_error_t* %helper_error_t to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %12)
  ret i64 0

helper_merge:                                     ; preds = %entry
  %13 = bitcast %buffer_64_t* %lookup_buf_map to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %13, i8 0, i64 68, i1 false)
  %14 = getelementptr %buffer_64_t, %buffer_64_t* %lookup_buf_map, i32 0, i32 0
  %15 = trunc i64 %length.select to i32
  store i32 %15, i32* %14
  %16 = getelementptr %buffer_64_t, %buffer_64_t* %lookup_buf_map, i32 0, i32 1
  %17 = bitcast i8* %0 to i64*
  %18 = getelementptr i64, i64* %17, i64 14
  %arg0 = load volatile i64, i64* %18
  %probe_read = call i64 inttoptr (i64 4 to i64 ([64 x i8]*, i32, i64)*)([64 x i8]* %16, i32 %15, i64 %arg0)
  %19 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %19)
  store i64 0, i64* %"@x_key"
  %pseudo2 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, %buffer_64_t*, i64)*)(i64 %pseudo2, i64* %"@x_key", %buffer_64_t* %lookup_buf_map, i64 0)
  %20 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %20)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
