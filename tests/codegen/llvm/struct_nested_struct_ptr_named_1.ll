; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

%helper_error_t = type <{ i64, i64, i32, i8 }>

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64, i64) #0

define i64 @"kprobe:f"(i8*) section "s_kprobe:f_1" {
entry:
  %"@x_key" = alloca i64
  %"@x_val" = alloca i64
  %"struct Bar.x" = alloca i32
  %"struct Foo.bar" = alloca i64
  %helper_error_t = alloca %helper_error_t
  %"lookup_$foo_key" = alloca i32
  %1 = bitcast i32* %"lookup_$foo_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i32 0, i32* %"lookup_$foo_key"
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 2)
  %"lookup_$foo_map" = call [8 x i8]* inttoptr (i64 1 to [8 x i8]* (i64, i32*)*)(i64 %pseudo, i32* %"lookup_$foo_key")
  %2 = bitcast i32* %"lookup_$foo_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %2)
  %3 = sext [8 x i8]* %"lookup_$foo_map" to i32
  %4 = icmp ne i32 %3, 0
  br i1 %4, label %helper_merge, label %helper_failure

helper_failure:                                   ; preds = %entry
  %5 = bitcast %helper_error_t* %helper_error_t to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %5)
  %6 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 0
  store i64 30006, i64* %6
  %7 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 1
  store i64 0, i64* %7
  %8 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 2
  store i32 %3, i32* %8
  %9 = getelementptr %helper_error_t, %helper_error_t* %helper_error_t, i64 0, i32 3
  store i8 1, i8* %9
  %pseudo1 = call i64 @llvm.bpf.pseudo(i64 1, i64 3)
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, %helper_error_t*, i64)*)(i8* %0, i64 %pseudo1, i64 4294967295, %helper_error_t* %helper_error_t, i64 21)
  %10 = bitcast %helper_error_t* %helper_error_t to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %10)
  ret i64 0

helper_merge:                                     ; preds = %entry
  %11 = bitcast [8 x i8]* %"lookup_$foo_map" to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %11, i8 0, i64 8, i1 false)
  %12 = bitcast [8 x i8]* %"lookup_$foo_map" to i8*
  %13 = bitcast i64 0 to i8 addrspace(64)*
  call void @llvm.memcpy.p0i8.p64i8.i64(i8* align 1 %12, i8 addrspace(64)* align 1 %13, i64 8, i1 false)
  %14 = add [8 x i8]* %"lookup_$foo_map", i64 0
  %15 = bitcast i64* %"struct Foo.bar" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %15)
  %probe_read = call i64 inttoptr (i64 4 to i64 (i64*, i32, [8 x i8]*)*)(i64* %"struct Foo.bar", i32 8, [8 x i8]* %14)
  %16 = load i64, i64* %"struct Foo.bar"
  %17 = bitcast i64* %"struct Foo.bar" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %17)
  %18 = add i64 %16, 0
  %19 = bitcast i32* %"struct Bar.x" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %19)
  %probe_read2 = call i64 inttoptr (i64 4 to i64 (i32*, i32, i64)*)(i32* %"struct Bar.x", i32 4, i64 %18)
  %20 = load i32, i32* %"struct Bar.x"
  %21 = sext i32 %20 to i64
  %22 = bitcast i32* %"struct Bar.x" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %22)
  %23 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %23)
  store i64 %21, i64* %"@x_val"
  %24 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %24)
  store i64 0, i64* %"@x_key"
  %pseudo3 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo3, i64* %"@x_key", i64* %"@x_val", i64 0)
  %25 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %25)
  %26 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %26)
  ret i64 0
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i1) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.memcpy.p0i8.p64i8.i64(i8* nocapture writeonly, i8 addrspace(64)* nocapture readonly, i64, i1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind }
