; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%"struct map_internal_repr_t" = type { ptr, ptr, ptr, ptr }
%"struct map_internal_repr_t.163" = type { ptr, ptr }
%uint8_uint8__tuple_t = type { i8, i8 }

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@AT_map = dso_local global %"struct map_internal_repr_t" zeroinitializer, section ".maps", !dbg !7
@ringbuf = dso_local global %"struct map_internal_repr_t.163" zeroinitializer, section ".maps", !dbg !25
@__bt__event_loss_counter = dso_local externally_initialized global [1 x [1 x i64]] zeroinitializer, section ".data.event_loss_counter", !dbg !39
@__bt__max_cpu_id = dso_local externally_initialized constant i64 0, section ".rodata", !dbg !44

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

; Function Attrs: nounwind
define i64 @begin_1(ptr %0) #0 section "s_begin_1" !dbg !50 {
entry:
  %"@map_val" = alloca i8, align 1
  %"@map_key" = alloca i8, align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@map_key")
  store i8 16, ptr %"@map_key", align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@map_val")
  store i8 32, ptr %"@map_val", align 1
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_map, ptr %"@map_key", ptr %"@map_val", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@map_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@map_key")
  %for_each_map_elem = call i64 inttoptr (i64 164 to ptr)(ptr @AT_map, ptr @map_for_each_cb, ptr null, i64 0)
  %for_each_map_elem1 = call i64 inttoptr (i64 164 to ptr)(ptr @AT_map, ptr @map_for_each_cb.1, ptr null, i64 0)
  ret i64 0
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nounwind
define internal i64 @map_for_each_cb(ptr %0, ptr %1, ptr %2, ptr %3) #0 section ".text" !dbg !55 {
for_body:
  %"$var" = alloca i8, align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$var")
  store i8 0, ptr %"$var", align 1
  %"$kv" = alloca %uint8_uint8__tuple_t, align 8
  %key = load i8, ptr %1, align 1
  %val = load i8, ptr %2, align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$kv")
  call void @llvm.memset.p0.i64(ptr align 1 %"$kv", i8 0, i64 2, i1 false)
  %4 = getelementptr %uint8_uint8__tuple_t, ptr %"$kv", i32 0, i32 0
  store i8 %key, ptr %4, align 1
  %5 = getelementptr %uint8_uint8__tuple_t, ptr %"$kv", i32 0, i32 1
  store i8 %val, ptr %5, align 1
  store i8 1, ptr %"$var", align 1
  br label %for_continue

for_continue:                                     ; preds = %for_body
  ret i64 0
}

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

; Function Attrs: nounwind
define internal i64 @map_for_each_cb.1(ptr %0, ptr %1, ptr %2, ptr %3) #0 section ".text" !dbg !63 {
for_body:
  %"$var" = alloca i8, align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$var")
  store i8 0, ptr %"$var", align 1
  %"$kv" = alloca %uint8_uint8__tuple_t, align 8
  %key = load i8, ptr %1, align 1
  %val = load i8, ptr %2, align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$kv")
  call void @llvm.memset.p0.i64(ptr align 1 %"$kv", i8 0, i64 2, i1 false)
  %4 = getelementptr %uint8_uint8__tuple_t, ptr %"$kv", i32 0, i32 0
  store i8 %key, ptr %4, align 1
  %5 = getelementptr %uint8_uint8__tuple_t, ptr %"$kv", i32 0, i32 1
  store i8 %val, ptr %5, align 1
  store i8 1, ptr %"$var", align 1
  br label %for_continue

for_continue:                                     ; preds = %for_body
  ret i64 0
}

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #2 = { nocallback nofree nounwind willreturn memory(argmem: write) }

!llvm.dbg.cu = !{!46}
!llvm.module.flags = !{!48, !49}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "LICENSE", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 32, elements: !5)
!4 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!5 = !{!6}
!6 = !DISubrange(count: 4, lowerBound: 0)
!7 = !DIGlobalVariableExpression(var: !8, expr: !DIExpression())
!8 = distinct !DIGlobalVariable(name: "AT_map", linkageName: "global", scope: !2, file: !2, type: !9, isLocal: false, isDefinition: true)
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
!40 = distinct !DIGlobalVariable(name: "__bt__event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !41, isLocal: false, isDefinition: true)
!41 = !DICompositeType(tag: DW_TAG_array_type, baseType: !42, size: 64, elements: !15)
!42 = !DICompositeType(tag: DW_TAG_array_type, baseType: !43, size: 64, elements: !15)
!43 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!44 = !DIGlobalVariableExpression(var: !45, expr: !DIExpression())
!45 = distinct !DIGlobalVariable(name: "__bt__max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !43, isLocal: false, isDefinition: true)
!46 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !47)
!47 = !{!0, !7, !25, !39, !44}
!48 = !{i32 2, !"Debug Info Version", i32 3}
!49 = !{i32 7, !"uwtable", i32 0}
!50 = distinct !DISubprogram(name: "begin_1", linkageName: "begin_1", scope: !2, file: !2, type: !51, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !46, retainedNodes: !53)
!51 = !DISubroutineType(types: !52)
!52 = !{!43, !23}
!53 = !{!54}
!54 = !DILocalVariable(name: "ctx", arg: 1, scope: !50, file: !2, type: !23)
!55 = distinct !DISubprogram(name: "map_for_each_cb", linkageName: "map_for_each_cb", scope: !2, file: !2, type: !56, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !46, retainedNodes: !58)
!56 = !DISubroutineType(types: !57)
!57 = !{!43, !23, !23, !23, !23}
!58 = !{!59, !60, !61, !62}
!59 = !DILocalVariable(name: "map", arg: 1, scope: !55, file: !2, type: !23)
!60 = !DILocalVariable(name: "key", arg: 2, scope: !55, file: !2, type: !23)
!61 = !DILocalVariable(name: "value", arg: 3, scope: !55, file: !2, type: !23)
!62 = !DILocalVariable(name: "ctx", arg: 4, scope: !55, file: !2, type: !23)
!63 = distinct !DISubprogram(name: "map_for_each_cb_1", linkageName: "map_for_each_cb_1", scope: !2, file: !2, type: !56, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !46, retainedNodes: !64)
!64 = !{!65, !66, !67, !68}
!65 = !DILocalVariable(name: "map", arg: 1, scope: !63, file: !2, type: !23)
!66 = !DILocalVariable(name: "key", arg: 2, scope: !63, file: !2, type: !23)
!67 = !DILocalVariable(name: "value", arg: 3, scope: !63, file: !2, type: !23)
!68 = !DILocalVariable(name: "ctx", arg: 4, scope: !63, file: !2, type: !23)
