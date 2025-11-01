; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%"struct map_internal_repr_t" = type { ptr, ptr, ptr, ptr }
%"struct map_internal_repr_t.616" = type { ptr, ptr }
%inet = type { i64, [16 x i8] }

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@AT_x = dso_local global %"struct map_internal_repr_t" zeroinitializer, section ".maps", !dbg !7
@ringbuf = dso_local global %"struct map_internal_repr_t.616" zeroinitializer, section ".maps", !dbg !29
@__bt__event_loss_counter = dso_local externally_initialized global [1 x [1 x i64]] zeroinitializer, section ".data.event_loss_counter", !dbg !43
@__bt__max_cpu_id = dso_local externally_initialized constant i64 0, section ".rodata", !dbg !48

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

; Function Attrs: nounwind
define i64 @kprobe_f_1(ptr %0) #0 section "s_kprobe_f_1" !dbg !54 {
entry:
  %"@x_val" = alloca i8, align 1
  %inet = alloca %inet, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %inet)
  %1 = getelementptr %inet, ptr %inet, i64 0, i32 0
  store i64 2, ptr %1, align 8
  %2 = getelementptr %inet, ptr %inet, i32 0, i32 1
  call void @llvm.memset.p0.i64(ptr align 1 %2, i8 0, i64 16, i1 false)
  store i32 -1, ptr %2, align 4
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_val")
  store i8 1, ptr %"@x_val", align 1
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %inet, ptr %"@x_val", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %inet)
  ret i64 0
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #2 = { nocallback nofree nounwind willreturn memory(argmem: write) }

!llvm.dbg.cu = !{!50}
!llvm.module.flags = !{!52, !53}

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
!10 = !{!11, !17, !22, !27}
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
!23 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !24, size: 64)
!24 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 192, elements: !25)
!25 = !{!26}
!26 = !DISubrange(count: 24, lowerBound: 0)
!27 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !28, size: 64, offset: 192)
!28 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!29 = !DIGlobalVariableExpression(var: !30, expr: !DIExpression())
!30 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !31, isLocal: false, isDefinition: true)
!31 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !32)
!32 = !{!33, !38}
!33 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !34, size: 64)
!34 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !35, size: 64)
!35 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 864, elements: !36)
!36 = !{!37}
!37 = !DISubrange(count: 27, lowerBound: 0)
!38 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !39, size: 64, offset: 64)
!39 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !40, size: 64)
!40 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 8388608, elements: !41)
!41 = !{!42}
!42 = !DISubrange(count: 262144, lowerBound: 0)
!43 = !DIGlobalVariableExpression(var: !44, expr: !DIExpression())
!44 = distinct !DIGlobalVariable(name: "__bt__event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !45, isLocal: false, isDefinition: true)
!45 = !DICompositeType(tag: DW_TAG_array_type, baseType: !46, size: 64, elements: !15)
!46 = !DICompositeType(tag: DW_TAG_array_type, baseType: !47, size: 64, elements: !15)
!47 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!48 = !DIGlobalVariableExpression(var: !49, expr: !DIExpression())
!49 = distinct !DIGlobalVariable(name: "__bt__max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !47, isLocal: false, isDefinition: true)
!50 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !51)
!51 = !{!0, !7, !29, !43, !48}
!52 = !{i32 2, !"Debug Info Version", i32 3}
!53 = !{i32 7, !"uwtable", i32 0}
!54 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !55, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !50, retainedNodes: !57)
!55 = !DISubroutineType(types: !56)
!56 = !{!47, !28}
!57 = !{!58}
!58 = !DILocalVariable(name: "ctx", arg: 1, scope: !54, file: !2, type: !28)
