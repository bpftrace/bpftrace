; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%"struct map_internal_repr_t" = type { ptr, ptr, ptr, ptr }
%"struct map_internal_repr_t.163" = type { ptr, ptr, ptr, ptr }
%"struct map_internal_repr_t.164" = type { ptr, ptr }

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@AT_x = dso_local global %"struct map_internal_repr_t" zeroinitializer, section ".maps", !dbg !7
@AT_y = dso_local global %"struct map_internal_repr_t.163" zeroinitializer, section ".maps", !dbg !23
@ringbuf = dso_local global %"struct map_internal_repr_t.164" zeroinitializer, section ".maps", !dbg !25
@__bt__max_cpu_id = dso_local externally_initialized constant i64 0, section ".rodata", !dbg !39
@__bt__event_loss_counter = dso_local externally_initialized global [1 x [1 x i64]] zeroinitializer, section ".data.event_loss_counter", !dbg !41
@__bt__map_key_buf = dso_local externally_initialized global [1 x [3 x [8 x i8]]] zeroinitializer, section ".data.map_key_buf", !dbg !45
@__bt__write_map_val_buf = dso_local externally_initialized global [1 x [1 x [1 x i8]]] zeroinitializer, section ".data.write_map_val_buf", !dbg !54
@__bt__read_map_val_buf = dso_local externally_initialized global [1 x [1 x [1 x i8]]] zeroinitializer, section ".data.read_map_val_buf", !dbg !59

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

; Function Attrs: nounwind
define i64 @kprobe_f_1(ptr %0) #0 section "s_kprobe_f_1" !dbg !65 {
entry:
  %get_cpu_id = call i64 inttoptr (i64 8 to ptr)() #1
  %1 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded = and i64 %get_cpu_id, %1
  %2 = getelementptr [1 x [3 x [8 x i8]]], ptr @__bt__map_key_buf, i64 0, i64 %cpu.id.bounded, i64 0, i64 0
  store i64 0, ptr %2, align 8
  %get_cpu_id1 = call i64 inttoptr (i64 8 to ptr)() #1
  %3 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded2 = and i64 %get_cpu_id1, %3
  %4 = getelementptr [1 x [1 x [1 x i8]]], ptr @__bt__write_map_val_buf, i64 0, i64 %cpu.id.bounded2, i64 0, i64 0
  store i8 1, ptr %4, align 1
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %2, ptr %4, i64 0)
  %get_cpu_id3 = call i64 inttoptr (i64 8 to ptr)() #1
  %5 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded4 = and i64 %get_cpu_id3, %5
  %6 = getelementptr [1 x [3 x [8 x i8]]], ptr @__bt__map_key_buf, i64 0, i64 %cpu.id.bounded4, i64 1, i64 0
  store i64 0, ptr %6, align 8
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
  %12 = getelementptr [1 x [3 x [8 x i8]]], ptr @__bt__map_key_buf, i64 0, i64 %cpu.id.bounded8, i64 2, i64 0
  store i64 0, ptr %12, align 8
  %get_cpu_id9 = call i64 inttoptr (i64 8 to ptr)() #1
  %13 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded10 = and i64 %get_cpu_id9, %13
  %14 = getelementptr [1 x [1 x [1 x i8]]], ptr @__bt__write_map_val_buf, i64 0, i64 %cpu.id.bounded10, i64 0, i64 0
  store i8 %10, ptr %14, align 1
  %update_elem11 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_y, ptr %12, ptr %14, i64 0)
  ret i64 0
}

attributes #0 = { nounwind }
attributes #1 = { memory(none) }

!llvm.dbg.cu = !{!61}
!llvm.module.flags = !{!63, !64}

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
!22 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!23 = !DIGlobalVariableExpression(var: !24, expr: !DIExpression())
!24 = distinct !DIGlobalVariable(name: "AT_y", linkageName: "global", scope: !2, file: !2, type: !9, isLocal: false, isDefinition: true)
!25 = !DIGlobalVariableExpression(var: !26, expr: !DIExpression())
!26 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !27, isLocal: false, isDefinition: true)
!27 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !28)
!28 = !{!29, !34}
!29 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !30, size: 64)
!30 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !31, size: 64)
!31 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 864, elements: !32)
!32 = !{!33}
!33 = !DISubrange(count: 27, lowerBound: 0)
!34 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !35, size: 64, offset: 64)
!35 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !36, size: 64)
!36 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 8388608, elements: !37)
!37 = !{!38}
!38 = !DISubrange(count: 262144, lowerBound: 0)
!39 = !DIGlobalVariableExpression(var: !40, expr: !DIExpression())
!40 = distinct !DIGlobalVariable(name: "__bt__max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !20, isLocal: false, isDefinition: true)
!41 = !DIGlobalVariableExpression(var: !42, expr: !DIExpression())
!42 = distinct !DIGlobalVariable(name: "__bt__event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !43, isLocal: false, isDefinition: true)
!43 = !DICompositeType(tag: DW_TAG_array_type, baseType: !44, size: 64, elements: !15)
!44 = !DICompositeType(tag: DW_TAG_array_type, baseType: !20, size: 64, elements: !15)
!45 = !DIGlobalVariableExpression(var: !46, expr: !DIExpression())
!46 = distinct !DIGlobalVariable(name: "__bt__map_key_buf", linkageName: "global", scope: !2, file: !2, type: !47, isLocal: false, isDefinition: true)
!47 = !DICompositeType(tag: DW_TAG_array_type, baseType: !48, size: 192, elements: !15)
!48 = !DICompositeType(tag: DW_TAG_array_type, baseType: !49, size: 192, elements: !52)
!49 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 64, elements: !50)
!50 = !{!51}
!51 = !DISubrange(count: 8, lowerBound: 0)
!52 = !{!53}
!53 = !DISubrange(count: 3, lowerBound: 0)
!54 = !DIGlobalVariableExpression(var: !55, expr: !DIExpression())
!55 = distinct !DIGlobalVariable(name: "__bt__write_map_val_buf", linkageName: "global", scope: !2, file: !2, type: !56, isLocal: false, isDefinition: true)
!56 = !DICompositeType(tag: DW_TAG_array_type, baseType: !57, size: 8, elements: !15)
!57 = !DICompositeType(tag: DW_TAG_array_type, baseType: !58, size: 8, elements: !15)
!58 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 8, elements: !15)
!59 = !DIGlobalVariableExpression(var: !60, expr: !DIExpression())
!60 = distinct !DIGlobalVariable(name: "__bt__read_map_val_buf", linkageName: "global", scope: !2, file: !2, type: !56, isLocal: false, isDefinition: true)
!61 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !62)
!62 = !{!0, !7, !23, !25, !39, !41, !45, !54, !59}
!63 = !{i32 2, !"Debug Info Version", i32 3}
!64 = !{i32 7, !"uwtable", i32 0}
!65 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !66, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !61, retainedNodes: !68)
!66 = !DISubroutineType(types: !67)
!67 = !{!20, !22}
!68 = !{!69}
!69 = !DILocalVariable(name: "ctx", arg: 1, scope: !65, file: !2, type: !22)
