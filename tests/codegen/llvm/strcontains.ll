; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%"struct map_t" = type { ptr, ptr }

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@ringbuf = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !7
@__bt__event_loss_counter = dso_local externally_initialized global [1 x [1 x i64]] zeroinitializer, section ".data.event_loss_counter", !dbg !22
@__bt__max_cpu_id = dso_local externally_initialized constant i64 0, section ".rodata", !dbg !29
@hello-test-world = global [17 x i8] c"hello-test-world\00"
@test = global [5 x i8] c"test\00"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

; Function Attrs: nounwind
define i64 @kprobe_foo_1(ptr %0) #0 section "s_kprobe_foo_1" !dbg !35 {
entry:
  %strcontains.j = alloca i64, align 8
  %strcontains.i = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %strcontains.i)
  store i64 0, ptr %strcontains.i, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %strcontains.j)
  br label %strcontains.empty.check

strcontains.empty.check:                          ; preds = %entry
  %1 = load i8, ptr @test, align 1
  %2 = icmp eq i8 %1, 0
  br i1 %2, label %strcontains.true, label %strcontains.outer.cond

strcontains.outer.cond:                           ; preds = %strcontains.outer.incr, %strcontains.empty.check
  %3 = load i64, ptr %strcontains.i, align 8
  %4 = icmp ult i64 %3, 17
  br i1 %4, label %strcontains.outer.cond.cmp, label %strcontains.false

strcontains.outer.cond.cmp:                       ; preds = %strcontains.outer.cond
  %5 = getelementptr i8, ptr @hello-test-world, i64 %3
  %6 = load i8, ptr %5, align 1
  %7 = icmp ne i8 %6, 0
  br i1 %7, label %strcontains.outer.body, label %strcontains.false

strcontains.outer.body:                           ; preds = %strcontains.outer.cond.cmp
  store i64 0, ptr %strcontains.j, align 8
  br label %strcontains.inner.cond

strcontains.inner.cond:                           ; preds = %strcontains.inner.incr, %strcontains.outer.body
  %8 = load i64, ptr %strcontains.j, align 8
  %9 = icmp ult i64 %8, 5
  br i1 %9, label %strcontains.inner.body, label %strcontains.outer.incr

strcontains.inner.body:                           ; preds = %strcontains.inner.cond
  %10 = getelementptr i8, ptr @test, i64 %8
  %11 = load i8, ptr %10, align 1
  %12 = icmp eq i8 %11, 0
  br i1 %12, label %strcontains.true, label %strcontains.inner.notnull

strcontains.inner.notnull:                        ; preds = %strcontains.inner.body
  %13 = add i64 %3, %8
  %14 = icmp uge i64 %13, 17
  br i1 %14, label %strcontains.outer.incr, label %strcontains.inner.cmp

strcontains.inner.cmp:                            ; preds = %strcontains.inner.notnull
  %15 = getelementptr i8, ptr @hello-test-world, i64 %13
  %16 = load i8, ptr %15, align 1
  %17 = icmp ne i8 %16, %11
  br i1 %17, label %strcontains.outer.incr, label %strcontains.inner.incr

strcontains.inner.incr:                           ; preds = %strcontains.inner.cmp
  %18 = load i64, ptr %strcontains.j, align 8
  %19 = add i64 %18, 1
  store i64 %19, ptr %strcontains.j, align 8
  br label %strcontains.inner.cond

strcontains.outer.incr:                           ; preds = %strcontains.inner.cmp, %strcontains.inner.notnull, %strcontains.inner.cond
  %20 = load i64, ptr %strcontains.i, align 8
  %21 = add i64 %20, 1
  store i64 %21, ptr %strcontains.i, align 8
  br label %strcontains.outer.cond

strcontains.true:                                 ; preds = %strcontains.inner.body, %strcontains.empty.check
  br label %strcontains.done

strcontains.false:                                ; preds = %strcontains.outer.cond.cmp, %strcontains.outer.cond
  br label %strcontains.done

strcontains.done:                                 ; preds = %strcontains.true, %strcontains.false
  %result = phi i1 [ false, %strcontains.false ], [ true, %strcontains.true ]
  call void @llvm.lifetime.end.p0(i64 -1, ptr %strcontains.j)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %strcontains.i)
  %22 = zext i1 %result to i64
  ret i64 0
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }

!llvm.dbg.cu = !{!31}
!llvm.module.flags = !{!33, !34}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "LICENSE", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 32, elements: !5)
!4 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!5 = !{!6}
!6 = !DISubrange(count: 4, lowerBound: 0)
!7 = !DIGlobalVariableExpression(var: !8, expr: !DIExpression())
!8 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !9, isLocal: false, isDefinition: true)
!9 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !10)
!10 = !{!11, !17}
!11 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !12, size: 64)
!12 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !13, size: 64)
!13 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 864, elements: !15)
!14 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!15 = !{!16}
!16 = !DISubrange(count: 27, lowerBound: 0)
!17 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !18, size: 64, offset: 64)
!18 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !19, size: 64)
!19 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 8388608, elements: !20)
!20 = !{!21}
!21 = !DISubrange(count: 262144, lowerBound: 0)
!22 = !DIGlobalVariableExpression(var: !23, expr: !DIExpression())
!23 = distinct !DIGlobalVariable(name: "__bt__event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !24, isLocal: false, isDefinition: true)
!24 = !DICompositeType(tag: DW_TAG_array_type, baseType: !25, size: 64, elements: !27)
!25 = !DICompositeType(tag: DW_TAG_array_type, baseType: !26, size: 64, elements: !27)
!26 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!27 = !{!28}
!28 = !DISubrange(count: 1, lowerBound: 0)
!29 = !DIGlobalVariableExpression(var: !30, expr: !DIExpression())
!30 = distinct !DIGlobalVariable(name: "__bt__max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !26, isLocal: false, isDefinition: true)
!31 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !32)
!32 = !{!0, !7, !22, !29}
!33 = !{i32 2, !"Debug Info Version", i32 3}
!34 = !{i32 7, !"uwtable", i32 0}
!35 = distinct !DISubprogram(name: "kprobe_foo_1", linkageName: "kprobe_foo_1", scope: !2, file: !2, type: !36, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !31, retainedNodes: !39)
!36 = !DISubroutineType(types: !37)
!37 = !{!26, !38}
!38 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!39 = !{!40}
!40 = !DILocalVariable(name: "ctx", arg: 1, scope: !35, file: !2, type: !38)
