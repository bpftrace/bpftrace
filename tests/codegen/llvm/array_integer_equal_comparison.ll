; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"kprobe:f"(i8* %0) section "s_kprobe:f_1" {
entry:
  %perfdata = alloca i64, align 8
  %arraycmp.result = alloca i1, align 1
  %rr = alloca i32, align 4
  %ll = alloca i32, align 4
  %"$b" = alloca i64, align 8
  %1 = bitcast i64* %"$b" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 0, i64* %"$b", align 8
  %"$a" = alloca i64, align 8
  %2 = bitcast i64* %"$a" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %2)
  store i64 0, i64* %"$a", align 8
  %3 = bitcast i8* %0 to i64*
  %4 = getelementptr i64, i64* %3, i64 14
  %arg0 = load volatile i64, i64* %4, align 8
  %5 = add i64 %arg0, 0
  store i64 %5, i64* %"$a", align 8
  %6 = bitcast i8* %0 to i64*
  %7 = getelementptr i64, i64* %6, i64 14
  %arg01 = load volatile i64, i64* %7, align 8
  %8 = add i64 %arg01, 0
  store i64 %8, i64* %"$b", align 8
  %9 = load i64, i64* %"$a", align 8
  %10 = load i64, i64* %"$b", align 8
  %11 = bitcast i32* %ll to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %11)
  %12 = bitcast i32* %rr to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %12)
  %13 = bitcast i1* %arraycmp.result to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %13)
  store i1 false, i1* %arraycmp.result, align 1
  %14 = add i64 %9, 0
  %probe_read_kernel = call i64 inttoptr (i64 113 to i64 (i32*, i32, i64)*)(i32* %ll, i32 4, i64 %14)
  %15 = load i32, i32* %ll, align 4
  %16 = add i64 %10, 0
  %probe_read_kernel2 = call i64 inttoptr (i64 113 to i64 (i32*, i32, i64)*)(i32* %rr, i32 4, i64 %16)
  %17 = load i32, i32* %rr, align 4
  %arraycmp.cmp = icmp ne i32 %15, %17
  br i1 %arraycmp.cmp, label %arraycmp.false, label %arraycmp.loop

if_body:                                          ; preds = %arraycmp.false
  %18 = bitcast i64* %perfdata to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %18)
  store i64 30000, i64* %perfdata, align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, i64*, i64)*)(i8* %0, i64 %pseudo, i64 4294967295, i64* %perfdata, i64 8)
  %19 = bitcast i64* %perfdata to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %19)
  ret i64 0

if_end:                                           ; preds = %deadcode, %arraycmp.false
  ret i64 0

arraycmp.false:                                   ; preds = %arraycmp.done, %arraycmp.loop7, %arraycmp.loop3, %arraycmp.loop, %entry
  %20 = load i1, i1* %arraycmp.result, align 1
  %21 = bitcast i1* %arraycmp.result to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %21)
  %22 = bitcast i32* %ll to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %22)
  %23 = bitcast i32* %rr to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %23)
  %24 = zext i1 %20 to i64
  %true_cond = icmp ne i64 %24, 0
  br i1 %true_cond, label %if_body, label %if_end

arraycmp.done:                                    ; preds = %arraycmp.loop11
  store i1 true, i1* %arraycmp.result, align 1
  br label %arraycmp.false

arraycmp.loop:                                    ; preds = %entry
  %25 = add i64 %9, 4
  %probe_read_kernel4 = call i64 inttoptr (i64 113 to i64 (i32*, i32, i64)*)(i32* %ll, i32 4, i64 %25)
  %26 = load i32, i32* %ll, align 4
  %27 = add i64 %10, 4
  %probe_read_kernel5 = call i64 inttoptr (i64 113 to i64 (i32*, i32, i64)*)(i32* %rr, i32 4, i64 %27)
  %28 = load i32, i32* %rr, align 4
  %arraycmp.cmp6 = icmp ne i32 %26, %28
  br i1 %arraycmp.cmp6, label %arraycmp.false, label %arraycmp.loop3

arraycmp.loop3:                                   ; preds = %arraycmp.loop
  %29 = add i64 %9, 8
  %probe_read_kernel8 = call i64 inttoptr (i64 113 to i64 (i32*, i32, i64)*)(i32* %ll, i32 4, i64 %29)
  %30 = load i32, i32* %ll, align 4
  %31 = add i64 %10, 8
  %probe_read_kernel9 = call i64 inttoptr (i64 113 to i64 (i32*, i32, i64)*)(i32* %rr, i32 4, i64 %31)
  %32 = load i32, i32* %rr, align 4
  %arraycmp.cmp10 = icmp ne i32 %30, %32
  br i1 %arraycmp.cmp10, label %arraycmp.false, label %arraycmp.loop7

arraycmp.loop7:                                   ; preds = %arraycmp.loop3
  %33 = add i64 %9, 12
  %probe_read_kernel12 = call i64 inttoptr (i64 113 to i64 (i32*, i32, i64)*)(i32* %ll, i32 4, i64 %33)
  %34 = load i32, i32* %ll, align 4
  %35 = add i64 %10, 12
  %probe_read_kernel13 = call i64 inttoptr (i64 113 to i64 (i32*, i32, i64)*)(i32* %rr, i32 4, i64 %35)
  %36 = load i32, i32* %rr, align 4
  %arraycmp.cmp14 = icmp ne i32 %34, %36
  br i1 %arraycmp.cmp14, label %arraycmp.false, label %arraycmp.loop11

arraycmp.loop11:                                  ; preds = %arraycmp.loop7
  br label %arraycmp.done

deadcode:                                         ; No predecessors!
  br label %if_end
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }
