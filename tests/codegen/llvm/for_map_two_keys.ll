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
@max_cpu_id = dso_local externally_initialized constant i64 zeroinitializer, section ".rodata", !dbg !62
@tuple_buf = dso_local externally_initialized global [1 x [2 x [24 x i8]]] zeroinitializer, section ".data.tuple_buf", !dbg !64

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @BEGIN_1(ptr %0) section "s_BEGIN_1" !dbg !75 {
entry:
  %"@map_val" = alloca i64, align 8
  %get_cpu_id = call i64 inttoptr (i64 8 to ptr)()
  %1 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded = and i64 %get_cpu_id, %1
  %2 = getelementptr [1 x [2 x [24 x i8]]], ptr @tuple_buf, i64 0, i64 %cpu.id.bounded, i64 0, i64 0
  call void @llvm.memset.p0.i64(ptr align 1 %2, i8 0, i64 16, i1 false)
  %3 = getelementptr %int64_int64__tuple_t, ptr %2, i32 0, i32 0
  store i64 16, ptr %3, align 8
  %4 = getelementptr %int64_int64__tuple_t, ptr %2, i32 0, i32 1
  store i64 17, ptr %4, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@map_val")
  store i64 32, ptr %"@map_val", align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_map, ptr %2, ptr %"@map_val", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@map_val")
  %for_each_map_elem = call i64 inttoptr (i64 164 to ptr)(ptr @AT_map, ptr @map_for_each_cb, ptr null, i64 0)
  ret i64 0
}

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #2

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #2

define internal i64 @map_for_each_cb(ptr %0, ptr %1, ptr %2, ptr %3) section ".text" !dbg !81 {
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
declare void @llvm.memcpy.p0.p0.i64(ptr noalias nocapture writeonly %0, ptr noalias nocapture readonly %1, i64 %2, i1 immarg %3) #3

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nounwind willreturn memory(argmem: write) }
attributes #2 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #3 = { nocallback nofree nounwind willreturn memory(argmem: readwrite) }

!llvm.dbg.cu = !{!72}
!llvm.module.flags = !{!74}

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
!63 = distinct !DIGlobalVariable(name: "max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !21, isLocal: false, isDefinition: true)
!64 = !DIGlobalVariableExpression(var: !65, expr: !DIExpression())
!65 = distinct !DIGlobalVariable(name: "tuple_buf", linkageName: "global", scope: !2, file: !2, type: !66, isLocal: false, isDefinition: true)
!66 = !DICompositeType(tag: DW_TAG_array_type, baseType: !67, size: 384, elements: !9)
!67 = !DICompositeType(tag: DW_TAG_array_type, baseType: !68, size: 384, elements: !32)
!68 = !DICompositeType(tag: DW_TAG_array_type, baseType: !69, size: 192, elements: !70)
!69 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!70 = !{!71}
!71 = !DISubrange(count: 24, lowerBound: 0)
!72 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !73)
!73 = !{!0, !25, !44, !58, !62, !64}
!74 = !{i32 2, !"Debug Info Version", i32 3}
!75 = distinct !DISubprogram(name: "BEGIN_1", linkageName: "BEGIN_1", scope: !2, file: !2, type: !76, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !72, retainedNodes: !79)
!76 = !DISubroutineType(types: !77)
!77 = !{!21, !78}
!78 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !69, size: 64)
!79 = !{!80}
!80 = !DILocalVariable(name: "ctx", arg: 1, scope: !75, file: !2, type: !78)
!81 = distinct !DISubprogram(name: "map_for_each_cb", linkageName: "map_for_each_cb", scope: !2, file: !2, type: !76, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !72, retainedNodes: !82)
!82 = !{!83}
!83 = !DILocalVariable(name: "ctx", arg: 1, scope: !81, file: !2, type: !78)
