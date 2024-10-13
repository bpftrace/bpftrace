; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr, ptr, ptr }
%"struct map_t.1" = type { ptr, ptr }
%"struct map_t.2" = type { ptr, ptr, ptr, ptr }
%int64_int64__tuple_t = type { i64, i64 }
%"(int64,int64)_int64__tuple_t" = type { %int64_int64__tuple_t, i64 }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_map = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@AT_x = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !25
@ringbuf = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !44
@event_loss_counter = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !58
@write_map_val_buf = dso_local externally_initialized global [1 x [1 x [8 x i8]]] zeroinitializer, section ".data.write_map_val_buf", !dbg !62
@max_cpu_id = dso_local externally_initialized constant i64 zeroinitializer, section ".rodata", !dbg !70
@tuple_buf = dso_local externally_initialized global [1 x [2 x [24 x i8]]] zeroinitializer, section ".data.tuple_buf", !dbg !72

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @BEGIN_1(ptr %0) section "s_BEGIN_1" !dbg !82 {
entry:
  %get_cpu_id = call i64 inttoptr (i64 8 to ptr)()
  %1 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded = and i64 %get_cpu_id, %1
  %2 = getelementptr [1 x [2 x [24 x i8]]], ptr @tuple_buf, i64 0, i64 %cpu.id.bounded, i64 0, i64 0
  call void @llvm.memset.p0.i64(ptr align 1 %2, i8 0, i64 16, i1 false)
  %3 = getelementptr %int64_int64__tuple_t, ptr %2, i32 0, i32 0
  store i64 16, ptr %3, align 8
  %4 = getelementptr %int64_int64__tuple_t, ptr %2, i32 0, i32 1
  store i64 17, ptr %4, align 8
  %get_cpu_id1 = call i64 inttoptr (i64 8 to ptr)()
  %5 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded2 = and i64 %get_cpu_id1, %5
  %6 = getelementptr [1 x [1 x [8 x i8]]], ptr @write_map_val_buf, i64 0, i64 %cpu.id.bounded2, i64 0, i64 0
  store i64 32, ptr %6, align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_map, ptr %2, ptr %6, i64 0)
  %for_each_map_elem = call i64 inttoptr (i64 164 to ptr)(ptr @AT_map, ptr @map_for_each_cb, ptr null, i64 0)
  ret i64 0
}

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #1

define internal i64 @map_for_each_cb(ptr %0, ptr %1, ptr %2, ptr %3) section ".text" !dbg !88 {
  %"@x_key" = alloca i64, align 8
  %val = load i64, ptr %2, align 8
  %get_cpu_id = call i64 inttoptr (i64 8 to ptr)()
  %5 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded = and i64 %get_cpu_id, %5
  %6 = getelementptr [1 x [2 x [24 x i8]]], ptr @tuple_buf, i64 0, i64 %cpu.id.bounded, i64 1, i64 0
  call void @llvm.memset.p0.i64(ptr align 1 %6, i8 0, i64 24, i1 false)
  %7 = getelementptr %"(int64,int64)_int64__tuple_t", ptr %6, i32 0, i32 0
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %7, ptr align 1 %1, i64 16, i1 false)
  %8 = getelementptr %"(int64,int64)_int64__tuple_t", ptr %6, i32 0, i32 1
  store i64 %val, ptr %8, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key")
  store i64 0, ptr %"@x_key", align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %"@x_key", ptr %6, i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key")
  ret i64 0
}

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: readwrite)
declare void @llvm.memcpy.p0.p0.i64(ptr noalias nocapture writeonly %0, ptr noalias nocapture readonly %1, i64 %2, i1 immarg %3) #2

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #3

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #3

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nounwind willreturn memory(argmem: write) }
attributes #2 = { nocallback nofree nounwind willreturn memory(argmem: readwrite) }
attributes #3 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }

!llvm.dbg.cu = !{!79}
!llvm.module.flags = !{!81}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "AT_map", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !4)
!4 = !{!5, !11, !16, !23}
!5 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !6, size: 64)
!6 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !7, size: 64)
!7 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 32, elements: !9)
!8 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!9 = !{!10}
!10 = !DISubrange(count: 1, lowerBound: 0)
!11 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !12, size: 64, offset: 64)
!12 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !13, size: 64)
!13 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 131072, elements: !14)
!14 = !{!15}
!15 = !DISubrange(count: 4096, lowerBound: 0)
!16 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !17, size: 64, offset: 128)
!17 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !18, size: 64)
!18 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !19)
!19 = !{!20, !22}
!20 = !DIDerivedType(tag: DW_TAG_member, scope: !2, file: !2, baseType: !21, size: 64)
!21 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!22 = !DIDerivedType(tag: DW_TAG_member, scope: !2, file: !2, baseType: !21, size: 64, offset: 64)
!23 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !24, size: 64, offset: 192)
!24 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !21, size: 64)
!25 = !DIGlobalVariableExpression(var: !26, expr: !DIExpression())
!26 = distinct !DIGlobalVariable(name: "AT_x", linkageName: "global", scope: !2, file: !2, type: !27, isLocal: false, isDefinition: true)
!27 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !28)
!28 = !{!29, !34, !35, !38}
!29 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !30, size: 64)
!30 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !31, size: 64)
!31 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !32)
!32 = !{!33}
!33 = !DISubrange(count: 2, lowerBound: 0)
!34 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !6, size: 64, offset: 64)
!35 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !36, size: 64, offset: 128)
!36 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !37, size: 64)
!37 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!38 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !39, size: 64, offset: 192)
!39 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !40, size: 64)
!40 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 192, elements: !41)
!41 = !{!42, !43}
!42 = !DIDerivedType(tag: DW_TAG_member, scope: !2, file: !2, baseType: !18, size: 128)
!43 = !DIDerivedType(tag: DW_TAG_member, scope: !2, file: !2, baseType: !21, size: 64, offset: 128)
!44 = !DIGlobalVariableExpression(var: !45, expr: !DIExpression())
!45 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !46, isLocal: false, isDefinition: true)
!46 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !47)
!47 = !{!48, !53}
!48 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !49, size: 64)
!49 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !50, size: 64)
!50 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !51)
!51 = !{!52}
!52 = !DISubrange(count: 27, lowerBound: 0)
!53 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !54, size: 64, offset: 64)
!54 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !55, size: 64)
!55 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !56)
!56 = !{!57}
!57 = !DISubrange(count: 262144, lowerBound: 0)
!58 = !DIGlobalVariableExpression(var: !59, expr: !DIExpression())
!59 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !60, isLocal: false, isDefinition: true)
!60 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !61)
!61 = !{!29, !34, !35, !23}
!62 = !DIGlobalVariableExpression(var: !63, expr: !DIExpression())
!63 = distinct !DIGlobalVariable(name: "write_map_val_buf", linkageName: "global", scope: !2, file: !2, type: !64, isLocal: false, isDefinition: true)
!64 = !DICompositeType(tag: DW_TAG_array_type, baseType: !65, size: 64, elements: !9)
!65 = !DICompositeType(tag: DW_TAG_array_type, baseType: !66, size: 64, elements: !9)
!66 = !DICompositeType(tag: DW_TAG_array_type, baseType: !67, size: 64, elements: !68)
!67 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!68 = !{!69}
!69 = !DISubrange(count: 8, lowerBound: 0)
!70 = !DIGlobalVariableExpression(var: !71, expr: !DIExpression())
!71 = distinct !DIGlobalVariable(name: "max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !21, isLocal: false, isDefinition: true)
!72 = !DIGlobalVariableExpression(var: !73, expr: !DIExpression())
!73 = distinct !DIGlobalVariable(name: "tuple_buf", linkageName: "global", scope: !2, file: !2, type: !74, isLocal: false, isDefinition: true)
!74 = !DICompositeType(tag: DW_TAG_array_type, baseType: !75, size: 384, elements: !9)
!75 = !DICompositeType(tag: DW_TAG_array_type, baseType: !76, size: 384, elements: !32)
!76 = !DICompositeType(tag: DW_TAG_array_type, baseType: !67, size: 192, elements: !77)
!77 = !{!78}
!78 = !DISubrange(count: 24, lowerBound: 0)
!79 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !80)
!80 = !{!0, !25, !44, !58, !62, !70, !72}
!81 = !{i32 2, !"Debug Info Version", i32 3}
!82 = distinct !DISubprogram(name: "BEGIN_1", linkageName: "BEGIN_1", scope: !2, file: !2, type: !83, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !79, retainedNodes: !86)
!83 = !DISubroutineType(types: !84)
!84 = !{!21, !85}
!85 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !67, size: 64)
!86 = !{!87}
!87 = !DILocalVariable(name: "ctx", arg: 1, scope: !82, file: !2, type: !85)
!88 = distinct !DISubprogram(name: "map_for_each_cb", linkageName: "map_for_each_cb", scope: !2, file: !2, type: !83, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !79, retainedNodes: !89)
!89 = !{!90}
!90 = !DILocalVariable(name: "ctx", arg: 1, scope: !88, file: !2, type: !85)
