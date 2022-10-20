; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"kprobe:f"(i8* %0) section "s_kprobe:f_1" !dbg !4 {
entry:
  %key = alloca i32, align 4
  %perfdata = alloca i64, align 8
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
  %16 = getelementptr [4 x i32], [4 x i32]* %14, i32 0, i32 0
  %probe_read_kernel = call i64 inttoptr (i64 113 to i64 (i32*, i32, i32*)*)(i32* %v1, i32 4, i32* %16)
  %17 = load i32, i32* %v1, align 4
  %18 = getelementptr [4 x i32], [4 x i32]* %15, i32 0, i32 0
  %probe_read_kernel2 = call i64 inttoptr (i64 113 to i64 (i32*, i32, i32*)*)(i32* %v2, i32 4, i32* %18)
  %19 = load i32, i32* %v2, align 4
  %arraycmp.cmp = icmp ne i32 %17, %19
  br i1 %arraycmp.cmp, label %arraycmp.false, label %arraycmp.loop

if_body:                                          ; preds = %arraycmp.done
  %20 = bitcast i64* %perfdata to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %20)
  store i64 30000, i64* %perfdata, align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %ringbuf_output = call i64 inttoptr (i64 130 to i64 (i64, i64*, i64, i64)*)(i64 %pseudo, i64* %perfdata, i64 8, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

if_end:                                           ; preds = %deadcode, %arraycmp.done
  ret i64 0

arraycmp.false:                                   ; preds = %arraycmp.loop7, %arraycmp.loop3, %arraycmp.loop, %entry
  store i1 false, i1* %arraycmp.result, align 1
  br label %arraycmp.done

arraycmp.done:                                    ; preds = %arraycmp.false, %arraycmp.loop11
  %21 = load i1, i1* %arraycmp.result, align 1
  %22 = bitcast i1* %arraycmp.result to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %22)
  %23 = bitcast i32* %v1 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %23)
  %24 = bitcast i32* %v2 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %24)
  %25 = zext i1 %21 to i64
  %true_cond = icmp ne i64 %25, 0
  br i1 %true_cond, label %if_body, label %if_end

arraycmp.loop:                                    ; preds = %entry
  %26 = getelementptr [4 x i32], [4 x i32]* %14, i32 0, i32 1
  %probe_read_kernel4 = call i64 inttoptr (i64 113 to i64 (i32*, i32, i32*)*)(i32* %v1, i32 4, i32* %26)
  %27 = load i32, i32* %v1, align 4
  %28 = getelementptr [4 x i32], [4 x i32]* %15, i32 0, i32 1
  %probe_read_kernel5 = call i64 inttoptr (i64 113 to i64 (i32*, i32, i32*)*)(i32* %v2, i32 4, i32* %28)
  %29 = load i32, i32* %v2, align 4
  %arraycmp.cmp6 = icmp ne i32 %27, %29
  br i1 %arraycmp.cmp6, label %arraycmp.false, label %arraycmp.loop3

arraycmp.loop3:                                   ; preds = %arraycmp.loop
  %30 = getelementptr [4 x i32], [4 x i32]* %14, i32 0, i32 2
  %probe_read_kernel8 = call i64 inttoptr (i64 113 to i64 (i32*, i32, i32*)*)(i32* %v1, i32 4, i32* %30)
  %31 = load i32, i32* %v1, align 4
  %32 = getelementptr [4 x i32], [4 x i32]* %15, i32 0, i32 2
  %probe_read_kernel9 = call i64 inttoptr (i64 113 to i64 (i32*, i32, i32*)*)(i32* %v2, i32 4, i32* %32)
  %33 = load i32, i32* %v2, align 4
  %arraycmp.cmp10 = icmp ne i32 %31, %33
  br i1 %arraycmp.cmp10, label %arraycmp.false, label %arraycmp.loop7

arraycmp.loop7:                                   ; preds = %arraycmp.loop3
  %34 = getelementptr [4 x i32], [4 x i32]* %14, i32 0, i32 3
  %probe_read_kernel12 = call i64 inttoptr (i64 113 to i64 (i32*, i32, i32*)*)(i32* %v1, i32 4, i32* %34)
  %35 = load i32, i32* %v1, align 4
  %36 = getelementptr [4 x i32], [4 x i32]* %15, i32 0, i32 3
  %probe_read_kernel13 = call i64 inttoptr (i64 113 to i64 (i32*, i32, i32*)*)(i32* %v2, i32 4, i32* %36)
  %37 = load i32, i32* %v2, align 4
  %arraycmp.cmp14 = icmp ne i32 %35, %37
  br i1 %arraycmp.cmp14, label %arraycmp.false, label %arraycmp.loop11

arraycmp.loop11:                                  ; preds = %arraycmp.loop7
  br label %arraycmp.done

event_loss_counter:                               ; preds = %if_body
  %38 = bitcast i32* %key to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %38)
  store i32 0, i32* %key, align 4
  %pseudo15 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i64, i32*)*)(i64 %pseudo15, i32* %key)
  %map_lookup_cond = icmp ne i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

counter_merge:                                    ; preds = %lookup_merge, %if_body
  %39 = bitcast i64* %perfdata to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %39)
  ret i64 0

lookup_success:                                   ; preds = %event_loss_counter
  %40 = bitcast i8* %lookup_elem to i64*
  %41 = atomicrmw add i64* %40, i64 1 seq_cst
  br label %lookup_merge

lookup_failure:                                   ; preds = %event_loss_counter
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  %42 = bitcast i32* %key to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %42)
  br label %counter_merge

deadcode:                                         ; No predecessors!
  br label %if_end
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!3}

!0 = distinct !DICompileUnit(language: DW_LANG_C, file: !1, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, enums: !2)
!1 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!2 = !{}
!3 = !{i32 2, !"Debug Info Version", i32 3}
!4 = distinct !DISubprogram(name: "kprobe_f", linkageName: "kprobe_f", scope: !1, file: !1, type: !5, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !10)
!5 = !DISubroutineType(types: !6)
!6 = !{!7, !8}
!7 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!8 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !9, size: 64)
!9 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!10 = !{!11, !12}
!11 = !DILocalVariable(name: "var0", scope: !4, file: !1, type: !7)
!12 = !DILocalVariable(name: "var1", arg: 1, scope: !4, file: !1, type: !8)
