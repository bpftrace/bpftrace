; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr, ptr, ptr }
%"struct map_t.1" = type { ptr, ptr }
%"struct map_t.2" = type { ptr, ptr, ptr, ptr }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_x = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@AT_y = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !22
@ringbuf = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !24
@event_loss_counter = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !38
@map_key_buf = dso_local externally_initialized global [1 x [3 x [8 x i8]]] zeroinitializer, section ".data.map_key_buf", !dbg !40
@write_map_val_buf = dso_local externally_initialized global [1 x [1 x [8 x i8]]] zeroinitializer, section ".data.write_map_val_buf", !dbg !50
@max_cpu_id = dso_local externally_initialized constant i64 zeroinitializer, section ".rodata", !dbg !54
@read_map_val_buf = dso_local externally_initialized global [1 x [1 x [8 x i8]]] zeroinitializer, section ".data.read_map_val_buf", !dbg !56

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(ptr %0) section "s_kprobe_f_1" !dbg !61 {
entry:
  %get_cpu_id = call i64 inttoptr (i64 8 to ptr)()
  %1 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded = and i64 %get_cpu_id, %1
  %2 = getelementptr [1 x [3 x [8 x i8]]], ptr @map_key_buf, i64 0, i64 %cpu.id.bounded, i64 0, i64 0
  store i64 0, ptr %2, align 8
  %get_cpu_id1 = call i64 inttoptr (i64 8 to ptr)()
  %3 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded2 = and i64 %get_cpu_id1, %3
  %4 = getelementptr [1 x [1 x [8 x i8]]], ptr @write_map_val_buf, i64 0, i64 %cpu.id.bounded2, i64 0, i64 0
  store i64 1, ptr %4, align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %2, ptr %4, i64 0)
  %get_cpu_id3 = call i64 inttoptr (i64 8 to ptr)()
  %5 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded4 = and i64 %get_cpu_id3, %5
  %6 = getelementptr [1 x [3 x [8 x i8]]], ptr @map_key_buf, i64 0, i64 %cpu.id.bounded4, i64 1, i64 0
  store i64 0, ptr %6, align 8
  %lookup_elem = call ptr inttoptr (i64 1 to ptr)(ptr @AT_x, ptr %6)
  %get_cpu_id5 = call i64 inttoptr (i64 8 to ptr)()
  %7 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded6 = and i64 %get_cpu_id5, %7
  %8 = getelementptr [1 x [1 x [8 x i8]]], ptr @read_map_val_buf, i64 0, i64 %cpu.id.bounded6, i64 0, i64 0
  %map_lookup_cond = icmp ne ptr %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  %9 = load i64, ptr %lookup_elem, align 8
  store i64 %9, ptr %8, align 8
  br label %lookup_merge

lookup_failure:                                   ; preds = %entry
  store i64 0, ptr %8, align 8
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  %10 = load i64, ptr %8, align 8
  %get_cpu_id7 = call i64 inttoptr (i64 8 to ptr)()
  %11 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded8 = and i64 %get_cpu_id7, %11
  %12 = getelementptr [1 x [3 x [8 x i8]]], ptr @map_key_buf, i64 0, i64 %cpu.id.bounded8, i64 2, i64 0
  store i64 0, ptr %12, align 8
  %get_cpu_id9 = call i64 inttoptr (i64 8 to ptr)()
  %13 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded10 = and i64 %get_cpu_id9, %13
  %14 = getelementptr [1 x [1 x [8 x i8]]], ptr @write_map_val_buf, i64 0, i64 %cpu.id.bounded10, i64 0, i64 0
  store i64 %10, ptr %14, align 8
  %update_elem11 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_y, ptr %12, ptr %14, i64 0)
  ret i64 0
}

attributes #0 = { nounwind }

!llvm.dbg.cu = !{!58}
!llvm.module.flags = !{!60}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "AT_x", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !4)
!4 = !{!5, !11, !16, !19}
!5 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !6, size: 64)
!6 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !7, size: 64)
!7 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !9)
!8 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!9 = !{!10}
!10 = !DISubrange(count: 2, lowerBound: 0)
!11 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !12, size: 64, offset: 64)
!12 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !13, size: 64)
!13 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 32, elements: !14)
!14 = !{!15}
!15 = !DISubrange(count: 1, lowerBound: 0)
!16 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !17, size: 64, offset: 128)
!17 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !18, size: 64)
!18 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!19 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !20, size: 64, offset: 192)
!20 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !21, size: 64)
!21 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!22 = !DIGlobalVariableExpression(var: !23, expr: !DIExpression())
!23 = distinct !DIGlobalVariable(name: "AT_y", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!24 = !DIGlobalVariableExpression(var: !25, expr: !DIExpression())
!25 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !26, isLocal: false, isDefinition: true)
!26 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !27)
!27 = !{!28, !33}
!28 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !29, size: 64)
!29 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !30, size: 64)
!30 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !31)
!31 = !{!32}
!32 = !DISubrange(count: 27, lowerBound: 0)
!33 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !34, size: 64, offset: 64)
!34 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !35, size: 64)
!35 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !36)
!36 = !{!37}
!37 = !DISubrange(count: 262144, lowerBound: 0)
!38 = !DIGlobalVariableExpression(var: !39, expr: !DIExpression())
!39 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!40 = !DIGlobalVariableExpression(var: !41, expr: !DIExpression())
!41 = distinct !DIGlobalVariable(name: "map_key_buf", linkageName: "global", scope: !2, file: !2, type: !42, isLocal: false, isDefinition: true)
!42 = !DICompositeType(tag: DW_TAG_array_type, baseType: !43, size: 192, elements: !14)
!43 = !DICompositeType(tag: DW_TAG_array_type, baseType: !44, size: 192, elements: !48)
!44 = !DICompositeType(tag: DW_TAG_array_type, baseType: !45, size: 64, elements: !46)
!45 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!46 = !{!47}
!47 = !DISubrange(count: 8, lowerBound: 0)
!48 = !{!49}
!49 = !DISubrange(count: 3, lowerBound: 0)
!50 = !DIGlobalVariableExpression(var: !51, expr: !DIExpression())
!51 = distinct !DIGlobalVariable(name: "write_map_val_buf", linkageName: "global", scope: !2, file: !2, type: !52, isLocal: false, isDefinition: true)
!52 = !DICompositeType(tag: DW_TAG_array_type, baseType: !53, size: 64, elements: !14)
!53 = !DICompositeType(tag: DW_TAG_array_type, baseType: !44, size: 64, elements: !14)
!54 = !DIGlobalVariableExpression(var: !55, expr: !DIExpression())
!55 = distinct !DIGlobalVariable(name: "max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !21, isLocal: false, isDefinition: true)
!56 = !DIGlobalVariableExpression(var: !57, expr: !DIExpression())
!57 = distinct !DIGlobalVariable(name: "read_map_val_buf", linkageName: "global", scope: !2, file: !2, type: !52, isLocal: false, isDefinition: true)
!58 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !59)
!59 = !{!0, !22, !24, !38, !40, !50, !54, !56}
!60 = !{i32 2, !"Debug Info Version", i32 3}
!61 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !62, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !58, retainedNodes: !65)
!62 = !DISubroutineType(types: !63)
!63 = !{!21, !64}
!64 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !45, size: 64)
!65 = !{!66}
!66 = !DILocalVariable(name: "ctx", arg: 1, scope: !61, file: !2, type: !64)
