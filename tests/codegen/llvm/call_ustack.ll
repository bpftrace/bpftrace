; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%stack_t = type { i64, i32, i32 }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"kprobe:f"(i8* %0) section "s_kprobe:f_1" {
entry:
  %"@y_key" = alloca i64, align 8
  %stack_args4 = alloca %stack_t, align 8
  %"@x_key" = alloca i64, align 8
  %stack_args = alloca %stack_t, align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 3)
  %get_stackid = call i64 inttoptr (i64 27 to i64 (i8*, i64, i64)*)(i8* %0, i64 %pseudo, i64 256)
  %1 = bitcast %stack_t* %stack_args to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  %2 = getelementptr %stack_t, %stack_t* %stack_args, i64 0, i32 0
  store i64 %get_stackid, i64* %2, align 8
  %3 = getelementptr %stack_t, %stack_t* %stack_args, i64 0, i32 1
  %get_pid_tgid = call i64 inttoptr (i64 14 to i64 ()*)()
  %4 = trunc i64 %get_pid_tgid to i32
  store i32 %4, i32* %3, align 4
  %5 = getelementptr %stack_t, %stack_t* %stack_args, i64 0, i32 2
  store i32 0, i32* %5, align 4
  %6 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %6)
  store i64 0, i64* %"@x_key", align 8
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, %stack_t*, i64)*)(i64 %pseudo1, i64* %"@x_key", %stack_t* %stack_args, i64 0)
  %7 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %7)
  %pseudo2 = call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  %get_stackid3 = call i64 inttoptr (i64 27 to i64 (i8*, i64, i64)*)(i8* %0, i64 %pseudo2, i64 256)
  %8 = bitcast %stack_t* %stack_args4 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %8)
  %9 = getelementptr %stack_t, %stack_t* %stack_args4, i64 0, i32 0
  store i64 %get_stackid3, i64* %9, align 8
  %10 = getelementptr %stack_t, %stack_t* %stack_args4, i64 0, i32 1
  %get_pid_tgid5 = call i64 inttoptr (i64 14 to i64 ()*)()
  %11 = trunc i64 %get_pid_tgid5 to i32
  store i32 %11, i32* %10, align 4
  %12 = getelementptr %stack_t, %stack_t* %stack_args4, i64 0, i32 2
  store i32 0, i32* %12, align 4
  %13 = bitcast i64* %"@y_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %13)
  store i64 0, i64* %"@y_key", align 8
  %pseudo6 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem7 = call i64 inttoptr (i64 2 to i64 (i64, i64*, %stack_t*, i64)*)(i64 %pseudo6, i64* %"@y_key", %stack_t* %stack_args4, i64 0)
  %14 = bitcast i64* %"@y_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %14)
  ret i64 0
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }
