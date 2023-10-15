; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%inet_t = type { i64, [16 x i8] }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"kprobe:f"(i8* %0) section "s_kprobe:f_1" {
entry:
  %initial_value = alloca i64, align 8
  %inet = alloca %inet_t, align 8
  %1 = bitcast %inet_t* %inet to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  %2 = getelementptr %inet_t, %inet_t* %inet, i64 0, i32 0
  store i64 2, i64* %2, align 8
  %3 = getelementptr %inet_t, %inet_t* %inet, i32 0, i32 1
  %4 = bitcast [16 x i8]* %3 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %4, i8 0, i64 16, i1 false)
  %5 = bitcast [16 x i8]* %3 to i32*
  store i32 -1, i32* %5, align 4
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i64, %inet_t*)*)(i64 %pseudo, %inet_t* %inet)
  %cast = bitcast i8* %lookup_elem to i64*
  %6 = icmp eq i64* %cast, null
  br i1 %6, label %ptr_null, label %ptr_merge

ptr_null:                                         ; preds = %entry
  %7 = bitcast i64* %initial_value to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %7)
  store i64 0, i64* %initial_value, align 8
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, %inet_t*, i64*, i64)*)(i64 %pseudo1, %inet_t* %inet, i64* %initial_value, i64 0)
  %pseudo2 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %lookup_elem3 = call i8* inttoptr (i64 1 to i8* (i64, %inet_t*)*)(i64 %pseudo2, %inet_t* %inet)
  %cast4 = bitcast i8* %lookup_elem3 to i64*
  %8 = bitcast i64* %initial_value to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %8)
  br label %ptr_merge

ptr_merge:                                        ; preds = %ptr_null, %entry
  %9 = icmp ne i64* %cast4, null
  br i1 %9, label %ptr_not_null, label %merge

ptr_not_null:                                     ; preds = %ptr_merge
  %10 = load i64, i64* %cast4, align 8
  %11 = add i64 %10, 1
  store i64 %11, i64* %cast4, align 8
  br label %merge

merge:                                            ; preds = %ptr_not_null, %ptr_merge
  %12 = bitcast %inet_t* %inet to i8*
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
