; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

%buffer_64_t = type { i8, [64 x i8] }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

define i64 @"kprobe:f"(i8*) section "s_kprobe:f_1" {
entry:
  %"@x_key" = alloca i64
  %buffer = alloca %buffer_64_t
  %1 = bitcast i8* %0 to i64*
  %2 = getelementptr i64, i64* %1, i64 13
  %arg1 = load volatile i64, i64* %2
  %length.cmp = icmp ule i64 %arg1, 64
  %length.select = select i1 %length.cmp, i64 %arg1, i64 64
  %3 = bitcast %buffer_64_t* %buffer to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %3)
  %4 = getelementptr %buffer_64_t, %buffer_64_t* %buffer, i32 0, i32 0
  %5 = trunc i64 %length.select to i8
  store i8 %5, i8* %4
  %6 = getelementptr %buffer_64_t, %buffer_64_t* %buffer, i32 0, i32 1
  %7 = bitcast [64 x i8]* %6 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %7, i8 0, i64 64, i1 false)
  %8 = bitcast i8* %0 to i64*
  %9 = getelementptr i64, i64* %8, i64 14
  %arg0 = load volatile i64, i64* %9
  %10 = zext i8 %5 to i32
  %probe_read_kernel = call i64 inttoptr (i64 113 to i64 ([64 x i8]*, i32, i64)*)([64 x i8]* %6, i32 %10, i64 %arg0)
  %11 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %11)
  store i64 0, i64* %"@x_key"
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, %buffer_64_t*, i64)*)(i64 %pseudo, i64* %"@x_key", %buffer_64_t* %buffer, i64 0)
  %12 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %12)
  %13 = bitcast %buffer_64_t* %buffer to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %13)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i1) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
