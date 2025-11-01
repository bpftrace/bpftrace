; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%"struct map_internal_repr_t" = type { ptr, ptr, ptr, ptr }
%"struct map_internal_repr_t.616" = type { ptr, ptr, ptr, ptr }
%"struct map_internal_repr_t.617" = type { ptr, ptr }
%uint8_uint8__tuple_t = type { i8, i8 }
%"(uint8,uint8)_uint8__tuple_t" = type { %uint8_uint8__tuple_t, i8 }

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@AT_map = dso_local global %"struct map_internal_repr_t" zeroinitializer, section ".maps", !dbg !7
@AT_x = dso_local global %"struct map_internal_repr_t.616" zeroinitializer, section ".maps", !dbg !30
@ringbuf = dso_local global %"struct map_internal_repr_t.617" zeroinitializer, section ".maps", !dbg !44
@__bt__event_loss_counter = dso_local externally_initialized global [1 x [1 x i64]] zeroinitializer, section ".data.event_loss_counter", !dbg !58
@__bt__max_cpu_id = dso_local externally_initialized constant i64 0, section ".rodata", !dbg !62

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

; Function Attrs: nounwind
define i64 @begin_1(ptr %0) #0 section "s_begin_1" !dbg !68 {
entry:
  %"@map_val" = alloca i8, align 1
  %tuple = alloca %uint8_uint8__tuple_t, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %tuple)
  call void @llvm.memset.p0.i64(ptr align 1 %tuple, i8 0, i64 2, i1 false)
  %1 = getelementptr %uint8_uint8__tuple_t, ptr %tuple, i32 0, i32 0
  store i8 16, ptr %1, align 1
  %2 = getelementptr %uint8_uint8__tuple_t, ptr %tuple, i32 0, i32 1
  store i8 17, ptr %2, align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@map_val")
  store i8 32, ptr %"@map_val", align 1
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_map, ptr %tuple, ptr %"@map_val", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@map_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %tuple)
  %for_each_map_elem = call i64 inttoptr (i64 164 to ptr)(ptr @AT_map, ptr @map_for_each_cb, ptr null, i64 0)
  ret i64 0
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nounwind
define internal i64 @map_for_each_cb(ptr %0, ptr %1, ptr %2, ptr %3) #0 section ".text" !dbg !73 {
for_body:
  %"@x_key" = alloca i64, align 8
  %"$kv" = alloca %"(uint8,uint8)_uint8__tuple_t", align 8
  %val = load i8, ptr %2, align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$kv")
  call void @llvm.memset.p0.i64(ptr align 1 %"$kv", i8 0, i64 3, i1 false)
  %4 = getelementptr %"(uint8,uint8)_uint8__tuple_t", ptr %"$kv", i32 0, i32 0
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %4, ptr align 1 %1, i64 2, i1 false)
  %5 = getelementptr %"(uint8,uint8)_uint8__tuple_t", ptr %"$kv", i32 0, i32 1
  store i8 %val, ptr %5, align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key")
  store i64 0, ptr %"@x_key", align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %"@x_key", ptr %"$kv", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key")
  br label %for_continue

for_continue:                                     ; preds = %for_body
  ret i64 0
}

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: readwrite)
declare void @llvm.memcpy.p0.p0.i64(ptr noalias nocapture writeonly %0, ptr noalias nocapture readonly %1, i64 %2, i1 immarg %3) #3

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #2 = { nocallback nofree nounwind willreturn memory(argmem: write) }
attributes #3 = { nocallback nofree nounwind willreturn memory(argmem: readwrite) }

!llvm.dbg.cu = !{!64}
!llvm.module.flags = !{!66, !67}

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
!10 = !{!11, !17, !22, !28}
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
!24 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 16, elements: !25)
!25 = !{!26, !27}
!26 = !DIDerivedType(tag: DW_TAG_member, scope: !2, file: !2, baseType: !4, size: 8)
!27 = !DIDerivedType(tag: DW_TAG_member, scope: !2, file: !2, baseType: !4, size: 8, offset: 8)
!28 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !29, size: 64, offset: 192)
!29 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!30 = !DIGlobalVariableExpression(var: !31, expr: !DIExpression())
!31 = distinct !DIGlobalVariable(name: "AT_x", linkageName: "global", scope: !2, file: !2, type: !32, isLocal: false, isDefinition: true)
!32 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !33)
!33 = !{!11, !34, !35, !38}
!34 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !12, size: 64, offset: 64)
!35 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !36, size: 64, offset: 128)
!36 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !37, size: 64)
!37 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!38 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !39, size: 64, offset: 192)
!39 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !40, size: 64)
!40 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 24, elements: !41)
!41 = !{!42, !43}
!42 = !DIDerivedType(tag: DW_TAG_member, scope: !2, file: !2, baseType: !24, size: 16)
!43 = !DIDerivedType(tag: DW_TAG_member, scope: !2, file: !2, baseType: !4, size: 8, offset: 16)
!44 = !DIGlobalVariableExpression(var: !45, expr: !DIExpression())
!45 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !46, isLocal: false, isDefinition: true)
!46 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !47)
!47 = !{!48, !53}
!48 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !49, size: 64)
!49 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !50, size: 64)
!50 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 864, elements: !51)
!51 = !{!52}
!52 = !DISubrange(count: 27, lowerBound: 0)
!53 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !54, size: 64, offset: 64)
!54 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !55, size: 64)
!55 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 8388608, elements: !56)
!56 = !{!57}
!57 = !DISubrange(count: 262144, lowerBound: 0)
!58 = !DIGlobalVariableExpression(var: !59, expr: !DIExpression())
!59 = distinct !DIGlobalVariable(name: "__bt__event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !60, isLocal: false, isDefinition: true)
!60 = !DICompositeType(tag: DW_TAG_array_type, baseType: !61, size: 64, elements: !15)
!61 = !DICompositeType(tag: DW_TAG_array_type, baseType: !37, size: 64, elements: !15)
!62 = !DIGlobalVariableExpression(var: !63, expr: !DIExpression())
!63 = distinct !DIGlobalVariable(name: "__bt__max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !37, isLocal: false, isDefinition: true)
!64 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !65)
!65 = !{!0, !7, !30, !44, !58, !62}
!66 = !{i32 2, !"Debug Info Version", i32 3}
!67 = !{i32 7, !"uwtable", i32 0}
!68 = distinct !DISubprogram(name: "begin_1", linkageName: "begin_1", scope: !2, file: !2, type: !69, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !64, retainedNodes: !71)
!69 = !DISubroutineType(types: !70)
!70 = !{!37, !29}
!71 = !{!72}
!72 = !DILocalVariable(name: "ctx", arg: 1, scope: !68, file: !2, type: !29)
!73 = distinct !DISubprogram(name: "map_for_each_cb", linkageName: "map_for_each_cb", scope: !2, file: !2, type: !74, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !64, retainedNodes: !76)
!74 = !DISubroutineType(types: !75)
!75 = !{!37, !29, !29, !29, !29}
!76 = !{!77, !78, !79, !80}
!77 = !DILocalVariable(name: "map", arg: 1, scope: !73, file: !2, type: !29)
!78 = !DILocalVariable(name: "key", arg: 2, scope: !73, file: !2, type: !29)
!79 = !DILocalVariable(name: "value", arg: 3, scope: !73, file: !2, type: !29)
!80 = !DILocalVariable(name: "ctx", arg: 4, scope: !73, file: !2, type: !29)
