; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr }
%"struct map_t.0" = type { ptr, ptr, ptr, ptr }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@ringbuf = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@event_loss_counter = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !16
@hello-test-world = global [17 x i8] c"hello-test-world\00"
@test = global [5 x i8] c"test\00"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_foo_1(ptr %0) section "s_kprobe_foo_1" !dbg !39 {
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

!llvm.dbg.cu = !{!36}
!llvm.module.flags = !{!38}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !4)
!4 = !{!5, !11}
!5 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !6, size: 64)
!6 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !7, size: 64)
!7 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !9)
!8 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!9 = !{!10}
!10 = !DISubrange(count: 27, lowerBound: 0)
!11 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !12, size: 64, offset: 64)
!12 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !13, size: 64)
!13 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !14)
!14 = !{!15}
!15 = !DISubrange(count: 262144, lowerBound: 0)
!16 = !DIGlobalVariableExpression(var: !17, expr: !DIExpression())
!17 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !18, isLocal: false, isDefinition: true)
!18 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !19)
!19 = !{!20, !25, !30, !33}
!20 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !21, size: 64)
!21 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !22, size: 64)
!22 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !23)
!23 = !{!24}
!24 = !DISubrange(count: 2, lowerBound: 0)
!25 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !26, size: 64, offset: 64)
!26 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !27, size: 64)
!27 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 32, elements: !28)
!28 = !{!29}
!29 = !DISubrange(count: 1, lowerBound: 0)
!30 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !31, size: 64, offset: 128)
!31 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !32, size: 64)
!32 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!33 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !34, size: 64, offset: 192)
!34 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !35, size: 64)
!35 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!36 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !37)
!37 = !{!0, !16}
!38 = !{i32 2, !"Debug Info Version", i32 3}
!39 = distinct !DISubprogram(name: "kprobe_foo_1", linkageName: "kprobe_foo_1", scope: !2, file: !2, type: !40, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !36, retainedNodes: !44)
!40 = !DISubroutineType(types: !41)
!41 = !{!35, !42}
!42 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !43, size: 64)
!43 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!44 = !{!45}
!45 = !DILocalVariable(name: "ctx", arg: 1, scope: !39, file: !2, type: !42)
