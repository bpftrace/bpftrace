; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%"struct map_t" = type { ptr, ptr }

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@ringbuf = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !7
@event_loss_counter = dso_local externally_initialized global i64 0, section ".data.event_loss_counter", !dbg !22
@max_cpu_id = dso_local externally_initialized constant i64 0, section ".rodata", !dbg !25
@get_str_buf = dso_local externally_initialized global [1 x [1 x [1024 x i8]]] zeroinitializer, section ".data.get_str_buf", !dbg !27
@test = global [5 x i8] c"test\00"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

; Function Attrs: nounwind
define i64 @kprobe_foo_1(ptr %0) #0 section "s_kprobe_foo_1" !dbg !40 {
entry:
  %strcontains.j = alloca i64, align 8
  %strcontains.i = alloca i64, align 8
  %get_cpu_id = call i64 inttoptr (i64 8 to ptr)()
  %1 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded = and i64 %get_cpu_id, %1
  %2 = getelementptr [1 x [1 x [1024 x i8]]], ptr @get_str_buf, i64 0, i64 %cpu.id.bounded, i64 0, i64 0
  %probe_read_kernel = call i64 inttoptr (i64 113 to ptr)(ptr %2, i32 1024, ptr null)
  %3 = call ptr @llvm.preserve.static.offset(ptr %0)
  %4 = getelementptr i64, ptr %3, i64 14
  %arg0 = load volatile i64, ptr %4, align 8
  %probe_read_kernel_str = call i64 inttoptr (i64 115 to ptr)(ptr %2, i32 1024, i64 %arg0)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %strcontains.i)
  store i64 0, ptr %strcontains.i, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %strcontains.j)
  br label %strcontains.empty.check

strcontains.empty.check:                          ; preds = %entry
  %5 = load i8, ptr @test, align 1
  %6 = icmp eq i8 %5, 0
  br i1 %6, label %strcontains.true, label %strcontains.outer.cond

strcontains.outer.cond:                           ; preds = %strcontains.outer.incr, %strcontains.empty.check
  %7 = load i64, ptr %strcontains.i, align 8
  %8 = icmp ult i64 %7, 1024
  br i1 %8, label %strcontains.outer.cond.cmp, label %strcontains.false

strcontains.outer.cond.cmp:                       ; preds = %strcontains.outer.cond
  %9 = getelementptr i8, ptr %2, i64 %7
  %10 = load i8, ptr %9, align 1
  %11 = icmp ne i8 %10, 0
  br i1 %11, label %strcontains.outer.body, label %strcontains.false

strcontains.outer.body:                           ; preds = %strcontains.outer.cond.cmp
  store i64 0, ptr %strcontains.j, align 8
  br label %strcontains.inner.cond

strcontains.inner.cond:                           ; preds = %strcontains.inner.incr, %strcontains.outer.body
  %12 = load i64, ptr %strcontains.j, align 8
  %13 = icmp ult i64 %12, 5
  br i1 %13, label %strcontains.inner.body, label %strcontains.outer.incr

strcontains.inner.body:                           ; preds = %strcontains.inner.cond
  %14 = getelementptr i8, ptr @test, i64 %12
  %15 = load i8, ptr %14, align 1
  %16 = icmp eq i8 %15, 0
  br i1 %16, label %strcontains.true, label %strcontains.inner.notnull

strcontains.inner.notnull:                        ; preds = %strcontains.inner.body
  %17 = add i64 %7, %12
  %18 = icmp uge i64 %17, 1024
  br i1 %18, label %strcontains.outer.incr, label %strcontains.inner.cmp

strcontains.inner.cmp:                            ; preds = %strcontains.inner.notnull
  %19 = getelementptr i8, ptr %2, i64 %17
  %20 = load i8, ptr %19, align 1
  %21 = icmp ne i8 %20, %15
  br i1 %21, label %strcontains.outer.incr, label %strcontains.inner.incr

strcontains.inner.incr:                           ; preds = %strcontains.inner.cmp
  %22 = load i64, ptr %strcontains.j, align 8
  %23 = add i64 %22, 1
  store i64 %23, ptr %strcontains.j, align 8
  br label %strcontains.inner.cond

strcontains.outer.incr:                           ; preds = %strcontains.inner.cmp, %strcontains.inner.notnull, %strcontains.inner.cond
  %24 = load i64, ptr %strcontains.i, align 8
  %25 = add i64 %24, 1
  store i64 %25, ptr %strcontains.i, align 8
  br label %strcontains.outer.cond

strcontains.true:                                 ; preds = %strcontains.inner.body, %strcontains.empty.check
  br label %strcontains.done

strcontains.false:                                ; preds = %strcontains.outer.cond.cmp, %strcontains.outer.cond
  br label %strcontains.done

strcontains.done:                                 ; preds = %strcontains.true, %strcontains.false
  %result = phi i1 [ false, %strcontains.false ], [ true, %strcontains.true ]
  call void @llvm.lifetime.end.p0(i64 -1, ptr %strcontains.j)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %strcontains.i)
  %26 = zext i1 %result to i64
  ret i64 0
}

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare ptr @llvm.preserve.static.offset(ptr readnone %0) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #2

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #2

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }
attributes #2 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }

!llvm.dbg.cu = !{!36}
!llvm.module.flags = !{!38, !39}

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
!23 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !24, isLocal: false, isDefinition: true)
!24 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!25 = !DIGlobalVariableExpression(var: !26, expr: !DIExpression())
!26 = distinct !DIGlobalVariable(name: "max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !24, isLocal: false, isDefinition: true)
!27 = !DIGlobalVariableExpression(var: !28, expr: !DIExpression())
!28 = distinct !DIGlobalVariable(name: "get_str_buf", linkageName: "global", scope: !2, file: !2, type: !29, isLocal: false, isDefinition: true)
!29 = !DICompositeType(tag: DW_TAG_array_type, baseType: !30, size: 8192, elements: !34)
!30 = !DICompositeType(tag: DW_TAG_array_type, baseType: !31, size: 8192, elements: !34)
!31 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 8192, elements: !32)
!32 = !{!33}
!33 = !DISubrange(count: 1024, lowerBound: 0)
!34 = !{!35}
!35 = !DISubrange(count: 1, lowerBound: 0)
!36 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !37)
!37 = !{!0, !7, !22, !25, !27}
!38 = !{i32 2, !"Debug Info Version", i32 3}
!39 = !{i32 7, !"uwtable", i32 0}
!40 = distinct !DISubprogram(name: "kprobe_foo_1", linkageName: "kprobe_foo_1", scope: !2, file: !2, type: !41, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !36, retainedNodes: !44)
!41 = !DISubroutineType(types: !42)
!42 = !{!24, !43}
!43 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!44 = !{!45}
!45 = !DILocalVariable(name: "ctx", arg: 1, scope: !40, file: !2, type: !43)
