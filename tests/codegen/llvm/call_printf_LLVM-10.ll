; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

%printf_t = type { i64, i64, i64 }

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"kprobe:f"(i8* %0) local_unnamed_addr section "s_kprobe:f_1" {
entry:
  %"struct Foo.l" = alloca i64, align 8
  %"struct Foo.c" = alloca i8, align 1
  %printf_args = alloca %printf_t, align 8
  %1 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  %2 = getelementptr inbounds %printf_t, %printf_t* %printf_args, i64 0, i32 0
  store i64 0, i64* %2, align 8
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %"struct Foo.c")
  %probe_read = call i64 inttoptr (i64 4 to i64 (i8*, i32, i64)*)(i8* nonnull %"struct Foo.c", i32 1, i64 0)
  %3 = load i8, i8* %"struct Foo.c", align 1
  %4 = sext i8 %3 to i64
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %"struct Foo.c")
  %5 = getelementptr inbounds %printf_t, %printf_t* %printf_args, i64 0, i32 1
  store i64 %4, i64* %5, align 8
  %6 = bitcast i64* %"struct Foo.l" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %6)
  %probe_read1 = call i64 inttoptr (i64 4 to i64 (i64*, i32, i64)*)(i64* nonnull %"struct Foo.l", i32 8, i64 8)
  %7 = load i64, i64* %"struct Foo.l", align 8
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %6)
  %8 = getelementptr inbounds %printf_t, %printf_t* %printf_args, i64 0, i32 2
  store i64 %7, i64* %8, align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %get_cpu_id = call i64 inttoptr (i64 8 to i64 ()*)()
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %printf_t*, i64)*)(i8* %0, i64 %pseudo, i64 %get_cpu_id, %printf_t* nonnull %printf_args, i64 24)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  ret i64 0
}

; Function Attrs: argmemonly nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind willreturn }
