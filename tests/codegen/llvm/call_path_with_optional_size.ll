; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%"struct map_t" = type { ptr, ptr }

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@ringbuf = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !7
@__bt__event_loss_counter = dso_local externally_initialized global i64 0, section ".data.event_loss_counter", !dbg !22
@__bt__max_cpu_id = dso_local externally_initialized constant i64 0, section ".rodata", !dbg !25
@__bt__get_str_buf = dso_local externally_initialized global [1 x [1 x [1024 x i8]]] zeroinitializer, section ".data.get_str_buf", !dbg !27

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

; Function Attrs: nounwind
define i64 @fentry_mock_vmlinux_filp_close_1(ptr %0) #0 section "s_fentry_mock_vmlinux_filp_close_1" !dbg !40 {
entry:
  %get_cpu_id = call i64 inttoptr (i64 8 to ptr)()
  %1 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded = and i64 %get_cpu_id, %1
  %2 = getelementptr [1 x [1 x [1024 x i8]]], ptr @__bt__get_str_buf, i64 0, i64 %cpu.id.bounded, i64 0, i64 0
  %probe_read_kernel = call i64 inttoptr (i64 113 to ptr)(ptr %2, i32 1024, ptr null)
  %d_path = call i64 inttoptr (i64 147 to ptr)(ptr null, ptr %2, i32 48)
  ret i64 0
}

attributes #0 = { nounwind }

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
!23 = distinct !DIGlobalVariable(name: "__bt__event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !24, isLocal: false, isDefinition: true)
!24 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!25 = !DIGlobalVariableExpression(var: !26, expr: !DIExpression())
!26 = distinct !DIGlobalVariable(name: "__bt__max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !24, isLocal: false, isDefinition: true)
!27 = !DIGlobalVariableExpression(var: !28, expr: !DIExpression())
!28 = distinct !DIGlobalVariable(name: "__bt__get_str_buf", linkageName: "global", scope: !2, file: !2, type: !29, isLocal: false, isDefinition: true)
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
!40 = distinct !DISubprogram(name: "fentry_mock_vmlinux_filp_close_1", linkageName: "fentry_mock_vmlinux_filp_close_1", scope: !2, file: !2, type: !41, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !36, retainedNodes: !44)
!41 = !DISubroutineType(types: !42)
!42 = !{!24, !43}
!43 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!44 = !{!45}
!45 = !DILocalVariable(name: "ctx", arg: 1, scope: !40, file: !2, type: !43)
