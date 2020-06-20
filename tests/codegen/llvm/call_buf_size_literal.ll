; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

%buffer_1_t = type { i8, [1 x i8] }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

define i64 @"kprobe:f"(i8*) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %"@x_key" = alloca i64, align 8
  %buffer = alloca %buffer_1_t, align 8
  %1 = getelementptr inbounds %buffer_1_t, %buffer_1_t* %buffer, i64 0, i32 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  store i64 1, i8* %1, align 8
  %2 = getelementptr inbounds %buffer_1_t, %buffer_1_t* %buffer, i64 0, i32 1
  %3 = getelementptr i8, i8* %0, i64 112
  %4 = bitcast i8* %3 to i64*
  %arg0 = load volatile i64, i64* %4, align 8
  %probe_read = call i64 inttoptr (i64 4 to i64 ([1 x i8]*, i32, i64)*)([1 x i8]* nonnull %2, i64 1, i64 %arg0)
  %5 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %5)
  store i64 0, i64* %"@x_key", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, %buffer_1_t*, i64)*)(i64 %pseudo, i64* nonnull %"@x_key", %buffer_1_t* nonnull %buffer, i64 0)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %5)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
