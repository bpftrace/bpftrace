; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"kprobe:f"(i8* %0) section "s_kprobe:f_1" {
entry:
  %perfdata = alloca i64, align 8
  %n = alloca i32, align 4
  %i = alloca i32, align 4
  %arraycmp.result = alloca i1, align 1
  %v2 = alloca i32, align 4
  %v1 = alloca i32, align 4
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
  %11 = bitcast i32* %v1 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %11)
  %12 = bitcast i32* %v2 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %12)
  %13 = bitcast i1* %arraycmp.result to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %13)
  store i1 true, i1* %arraycmp.result, align 1
  %14 = inttoptr i64 %9 to [4 x i32]*
  %15 = inttoptr i64 %10 to [4 x i32]*
  %16 = bitcast i32* %i to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %16)
  %17 = bitcast i32* %n to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %17)
  store i32 0, i32* %i, align 4
  store i32 4, i32* %n, align 4
  br label %while_cond

if_body:                                          ; preds = %arraycmp.done
  %18 = bitcast i64* %perfdata to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %18)
  store i64 30000, i64* %perfdata, align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i64, i64, i64*, i64)*)(i8* %0, i64 %pseudo, i64 4294967295, i64* %perfdata, i64 8)
  %19 = bitcast i64* %perfdata to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %19)
  ret i64 0

if_end:                                           ; preds = %deadcode, %arraycmp.done
  ret i64 0

while_cond:                                       ; preds = %arraycmp.loop, %entry
  %20 = load i32, i32* %n, align 4
  %21 = load i32, i32* %i, align 4
  %size_check = icmp slt i32 %21, %20
  br i1 %size_check, label %while_body, label %arraycmp.done, !llvm.loop !0

while_body:                                       ; preds = %while_cond
  %22 = load i32, i32* %i, align 4
  %23 = getelementptr [4 x i32], [4 x i32]* %14, i32 0, i32 %22
  %probe_read_kernel = call i64 inttoptr (i64 113 to i64 (i32*, i32, i32*)*)(i32* %v1, i32 4, i32* %23)
  %24 = load i32, i32* %v1, align 4
  %25 = load i32, i32* %i, align 4
  %26 = getelementptr [4 x i32], [4 x i32]* %15, i32 0, i32 %25
  %probe_read_kernel2 = call i64 inttoptr (i64 113 to i64 (i32*, i32, i32*)*)(i32* %v2, i32 4, i32* %26)
  %27 = load i32, i32* %v2, align 4
  %arraycmp.cmp = icmp ne i32 %24, %27
  br i1 %arraycmp.cmp, label %arraycmp.false, label %arraycmp.loop

arraycmp.false:                                   ; preds = %while_body
  store i1 false, i1* %arraycmp.result, align 1
  br label %arraycmp.done

arraycmp.done:                                    ; preds = %arraycmp.false, %while_cond
  %28 = load i1, i1* %arraycmp.result, align 1
  %29 = bitcast i1* %arraycmp.result to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %29)
  %30 = bitcast i32* %v1 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %30)
  %31 = bitcast i32* %v2 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %31)
  %32 = zext i1 %28 to i64
  %true_cond = icmp ne i64 %32, 0
  br i1 %true_cond, label %if_body, label %if_end

arraycmp.loop:                                    ; preds = %while_body
  %33 = load i32, i32* %i, align 4
  %34 = add i32 %33, 1
  store i32 %34, i32* %i, align 4
  br label %while_cond

deadcode:                                         ; No predecessors!
  br label %if_end
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }

!0 = distinct !{!0, !1}
!1 = !{!"llvm.loop.unroll.disable"}
