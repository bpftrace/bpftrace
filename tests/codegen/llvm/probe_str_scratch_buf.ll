; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr }

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@AT_x = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !7
@ringbuf = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !26
@event_loss_counter = dso_local externally_initialized global i64 0, section ".data.event_loss_counter", !dbg !38
@max_cpu_id = dso_local externally_initialized constant i64 0, section ".rodata", !dbg !40
@map_key_buf = dso_local externally_initialized global [1 x [1 x [8 x i8]]] zeroinitializer, section ".data.map_key_buf", !dbg !42
@"tracepoint:sched:sched_one" = global [27 x i8] c"tracepoint:sched:sched_one\00"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

; Function Attrs: nounwind
define i64 @tracepoint_sched_sched_one_1(ptr %0) #0 section "s_tracepoint_sched_sched_one_1" !dbg !53 {
entry:
  %get_cpu_id = call i64 inttoptr (i64 8 to ptr)()
  %1 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded = and i64 %get_cpu_id, %1
  %2 = getelementptr [1 x [1 x [8 x i8]]], ptr @map_key_buf, i64 0, i64 %cpu.id.bounded, i64 0, i64 0
  store i64 0, ptr %2, align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %2, ptr @"tracepoint:sched:sched_one", i64 0)
  ret i64 1
}

attributes #0 = { nounwind }

!llvm.dbg.cu = !{!49}
!llvm.module.flags = !{!51, !52}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "LICENSE", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 32, elements: !5)
!4 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!5 = !{!6}
!6 = !DISubrange(count: 4, lowerBound: 0)
!7 = !DIGlobalVariableExpression(var: !8, expr: !DIExpression())
!8 = distinct !DIGlobalVariable(name: "AT_x", linkageName: "global", scope: !2, file: !2, type: !9, isLocal: false, isDefinition: true)
!9 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !10)
!10 = !{!11, !17, !18, !21}
!11 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !12, size: 64)
!12 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !13, size: 64)
!13 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 32, elements: !15)
!14 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!15 = !{!16}
!16 = !DISubrange(count: 1, lowerBound: 0)
!17 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !12, size: 64, offset: 64)
!18 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !19, size: 64, offset: 128)
!19 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !20, size: 64)
!20 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!21 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !22, size: 64, offset: 192)
!22 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !23, size: 64)
!23 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 216, elements: !24)
!24 = !{!25}
!25 = !DISubrange(count: 27, lowerBound: 0)
!26 = !DIGlobalVariableExpression(var: !27, expr: !DIExpression())
!27 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !28, isLocal: false, isDefinition: true)
!28 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !29)
!29 = !{!30, !33}
!30 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !31, size: 64)
!31 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !32, size: 64)
!32 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 864, elements: !24)
!33 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !34, size: 64, offset: 64)
!34 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !35, size: 64)
!35 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 8388608, elements: !36)
!36 = !{!37}
!37 = !DISubrange(count: 262144, lowerBound: 0)
!38 = !DIGlobalVariableExpression(var: !39, expr: !DIExpression())
!39 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !20, isLocal: false, isDefinition: true)
!40 = !DIGlobalVariableExpression(var: !41, expr: !DIExpression())
!41 = distinct !DIGlobalVariable(name: "max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !20, isLocal: false, isDefinition: true)
!42 = !DIGlobalVariableExpression(var: !43, expr: !DIExpression())
!43 = distinct !DIGlobalVariable(name: "map_key_buf", linkageName: "global", scope: !2, file: !2, type: !44, isLocal: false, isDefinition: true)
!44 = !DICompositeType(tag: DW_TAG_array_type, baseType: !45, size: 64, elements: !15)
!45 = !DICompositeType(tag: DW_TAG_array_type, baseType: !46, size: 64, elements: !15)
!46 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 64, elements: !47)
!47 = !{!48}
!48 = !DISubrange(count: 8, lowerBound: 0)
!49 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !50)
!50 = !{!0, !7, !26, !38, !40, !42}
!51 = !{i32 2, !"Debug Info Version", i32 3}
!52 = !{i32 7, !"uwtable", i32 0}
!53 = distinct !DISubprogram(name: "tracepoint_sched_sched_one_1", linkageName: "tracepoint_sched_sched_one_1", scope: !2, file: !2, type: !54, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !49, retainedNodes: !57)
!54 = !DISubroutineType(types: !55)
!55 = !{!20, !56}
!56 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!57 = !{!58}
!58 = !DILocalVariable(name: "ctx", arg: 1, scope: !53, file: !2, type: !56)
