; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%"struct map_internal_repr_t" = type { ptr, ptr, ptr, ptr }
%"struct map_internal_repr_t.616" = type { ptr, ptr, ptr, ptr }
%"struct map_internal_repr_t.617" = type { ptr, ptr }

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@AT_x = dso_local global %"struct map_internal_repr_t" zeroinitializer, section ".maps", !dbg !7
@AT_y = dso_local global %"struct map_internal_repr_t.616" zeroinitializer, section ".maps", !dbg !25
@ringbuf = dso_local global %"struct map_internal_repr_t.617" zeroinitializer, section ".maps", !dbg !34
@__bt__max_cpu_id = dso_local externally_initialized constant i64 0, section ".rodata", !dbg !48
@__bt__event_loss_counter = dso_local externally_initialized global [1 x [1 x i64]] zeroinitializer, section ".data.event_loss_counter", !dbg !51
@__bt__map_key_buf = dso_local externally_initialized global [1 x [2 x [1 x i8]]] zeroinitializer, section ".data.map_key_buf", !dbg !55
@__bt__write_map_val_buf = dso_local externally_initialized global [1 x [1 x [1 x i8]]] zeroinitializer, section ".data.write_map_val_buf", !dbg !62
@__bt__read_map_val_buf = dso_local externally_initialized global [1 x [1 x [1 x i8]]] zeroinitializer, section ".data.read_map_val_buf", !dbg !66
@yyyy = global [5 x i8] c"yyyy\00"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

; Function Attrs: nounwind
define i64 @kprobe_f_1(ptr %0) #0 section "s_kprobe_f_1" !dbg !72 {
entry:
  %get_cpu_id = call i64 inttoptr (i64 8 to ptr)() #1
  %1 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded = and i64 %get_cpu_id, %1
  %2 = getelementptr [1 x [2 x [1 x i8]]], ptr @__bt__map_key_buf, i64 0, i64 %cpu.id.bounded, i64 0, i64 0
  store i8 1, ptr %2, align 1
  %get_cpu_id1 = call i64 inttoptr (i64 8 to ptr)() #1
  %3 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded2 = and i64 %get_cpu_id1, %3
  %4 = getelementptr [1 x [1 x [1 x i8]]], ptr @__bt__write_map_val_buf, i64 0, i64 %cpu.id.bounded2, i64 0, i64 0
  store i8 1, ptr %4, align 1
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %2, ptr %4, i64 0)
  %get_cpu_id3 = call i64 inttoptr (i64 8 to ptr)() #1
  %5 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded4 = and i64 %get_cpu_id3, %5
  %6 = getelementptr [1 x [2 x [1 x i8]]], ptr @__bt__map_key_buf, i64 0, i64 %cpu.id.bounded4, i64 1, i64 0
  store i8 1, ptr %6, align 1
  %lookup_elem = call ptr inttoptr (i64 1 to ptr)(ptr @AT_x, ptr %6)
  %get_cpu_id5 = call i64 inttoptr (i64 8 to ptr)() #1
  %7 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded6 = and i64 %get_cpu_id5, %7
  %8 = getelementptr [1 x [1 x [1 x i8]]], ptr @__bt__read_map_val_buf, i64 0, i64 %cpu.id.bounded6, i64 0, i64 0
  %map_lookup_cond = icmp ne ptr %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  %9 = load i8, ptr %lookup_elem, align 1
  store i8 %9, ptr %8, align 1
  br label %lookup_merge

lookup_failure:                                   ; preds = %entry
  store i8 0, ptr %8, align 1
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  %10 = load i8, ptr %8, align 1
  %get_cpu_id7 = call i64 inttoptr (i64 8 to ptr)() #1
  %11 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded8 = and i64 %get_cpu_id7, %11
  %12 = getelementptr [1 x [1 x [1 x i8]]], ptr @__bt__write_map_val_buf, i64 0, i64 %cpu.id.bounded8, i64 0, i64 0
  store i8 %10, ptr %12, align 1
  %update_elem9 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_y, ptr @yyyy, ptr %12, i64 0)
  ret i64 0
}

attributes #0 = { nounwind }
attributes #1 = { memory(none) }

!llvm.dbg.cu = !{!68}
!llvm.module.flags = !{!70, !71}

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
!10 = !{!11, !17, !22, !24}
!11 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !12, size: 64)
!12 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !13, size: 64)
!13 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 32, elements: !15)
!14 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!15 = !{!16}
!16 = !DISubrange(count: 1, lowerBound: 0)
!17 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !18, size: 64, offset: 64)
!18 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !19, size: 64)
!19 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 131072, elements: !20)
!20 = !{!21}
!21 = !DISubrange(count: 4096, lowerBound: 0)
!22 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !23, size: 64, offset: 128)
!23 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!24 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !23, size: 64, offset: 192)
!25 = !DIGlobalVariableExpression(var: !26, expr: !DIExpression())
!26 = distinct !DIGlobalVariable(name: "AT_y", linkageName: "global", scope: !2, file: !2, type: !27, isLocal: false, isDefinition: true)
!27 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !28)
!28 = !{!11, !17, !29, !24}
!29 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !30, size: 64, offset: 128)
!30 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !31, size: 64)
!31 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 40, elements: !32)
!32 = !{!33}
!33 = !DISubrange(count: 5, lowerBound: 0)
!34 = !DIGlobalVariableExpression(var: !35, expr: !DIExpression())
!35 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !36, isLocal: false, isDefinition: true)
!36 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !37)
!37 = !{!38, !43}
!38 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !39, size: 64)
!39 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !40, size: 64)
!40 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 864, elements: !41)
!41 = !{!42}
!42 = !DISubrange(count: 27, lowerBound: 0)
!43 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !44, size: 64, offset: 64)
!44 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !45, size: 64)
!45 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 8388608, elements: !46)
!46 = !{!47}
!47 = !DISubrange(count: 262144, lowerBound: 0)
!48 = !DIGlobalVariableExpression(var: !49, expr: !DIExpression())
!49 = distinct !DIGlobalVariable(name: "__bt__max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !50, isLocal: false, isDefinition: true)
!50 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!51 = !DIGlobalVariableExpression(var: !52, expr: !DIExpression())
!52 = distinct !DIGlobalVariable(name: "__bt__event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !53, isLocal: false, isDefinition: true)
!53 = !DICompositeType(tag: DW_TAG_array_type, baseType: !54, size: 64, elements: !15)
!54 = !DICompositeType(tag: DW_TAG_array_type, baseType: !50, size: 64, elements: !15)
!55 = !DIGlobalVariableExpression(var: !56, expr: !DIExpression())
!56 = distinct !DIGlobalVariable(name: "__bt__map_key_buf", linkageName: "global", scope: !2, file: !2, type: !57, isLocal: false, isDefinition: true)
!57 = !DICompositeType(tag: DW_TAG_array_type, baseType: !58, size: 16, elements: !15)
!58 = !DICompositeType(tag: DW_TAG_array_type, baseType: !59, size: 16, elements: !60)
!59 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 8, elements: !15)
!60 = !{!61}
!61 = !DISubrange(count: 2, lowerBound: 0)
!62 = !DIGlobalVariableExpression(var: !63, expr: !DIExpression())
!63 = distinct !DIGlobalVariable(name: "__bt__write_map_val_buf", linkageName: "global", scope: !2, file: !2, type: !64, isLocal: false, isDefinition: true)
!64 = !DICompositeType(tag: DW_TAG_array_type, baseType: !65, size: 8, elements: !15)
!65 = !DICompositeType(tag: DW_TAG_array_type, baseType: !59, size: 8, elements: !15)
!66 = !DIGlobalVariableExpression(var: !67, expr: !DIExpression())
!67 = distinct !DIGlobalVariable(name: "__bt__read_map_val_buf", linkageName: "global", scope: !2, file: !2, type: !64, isLocal: false, isDefinition: true)
!68 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !69)
!69 = !{!0, !7, !25, !34, !48, !51, !55, !62, !66}
!70 = !{i32 2, !"Debug Info Version", i32 3}
!71 = !{i32 7, !"uwtable", i32 0}
!72 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !73, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !68, retainedNodes: !75)
!73 = !DISubroutineType(types: !74)
!74 = !{!50, !23}
!75 = !{!76}
!76 = !DILocalVariable(name: "ctx", arg: 1, scope: !72, file: !2, type: !23)
