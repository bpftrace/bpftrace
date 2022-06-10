; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"kprobe:do_nanosleep"(i8* %0) section "s_kprobe:do_nanosleep_1" {
entry:
  %"$c" = alloca i8, align 1
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %"$c")
  store i8 0, i8* %"$c", align 1
  %"struct Foo.c" = alloca i8, align 1
  %"$foo" = alloca i64, align 8
  %1 = bitcast i64* %"$foo" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 0, i64* %"$foo", align 8
  %2 = bitcast i8* %0 to i64*
  %3 = getelementptr i64, i64* %2, i64 14
  %arg0 = load volatile i64, i64* %3, align 8
  store i64 %arg0, i64* %"$foo", align 8
  br i1 true, label %if_body, label %if_end

if_body:                                          ; preds = %entry
  %4 = load i64, i64* %"$foo", align 8
  %5 = add i64 %4, 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %"struct Foo.c")
  %probe_read_kernel = call i64 inttoptr (i64 113 to i64 (i8*, i32, i64)*)(i8* %"struct Foo.c", i32 1, i64 %5)
  %6 = load i8, i8* %"struct Foo.c", align 1
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %"struct Foo.c")
  store i8 %6, i8* %"$c", align 1
  br label %if_end

if_end:                                           ; preds = %if_body, %entry
  ret i64 0
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }
