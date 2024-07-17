; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr, ptr, ptr }
%"struct map_t.1" = type { ptr, ptr }
%"struct map_t.2" = type { ptr, ptr, ptr, ptr }
%"string[4]_string[4]__tuple_t" = type { [4 x i8], [4 x i8] }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_map = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@AT_x = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !23
@ringbuf = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !36
@event_loss_counter = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !50

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @BEGIN_1(ptr %0) section "s_BEGIN_1" !dbg !67 {
entry:
  %str1 = alloca [4 x i8], align 1
  %str = alloca [4 x i8], align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %str)
  store [4 x i8] c"xyz\00", ptr %str, align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %str1)
  store [4 x i8] c"abc\00", ptr %str1, align 1
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_map, ptr %str1, ptr %str, i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %str)
  %for_each_map_elem = call i64 inttoptr (i64 164 to ptr)(ptr @AT_map, ptr @map_for_each_cb, ptr null, i64 0)
  ret i64 0
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

define internal i64 @map_for_each_cb(ptr %0, ptr %1, ptr %2, ptr %3) section ".text" !dbg !73 {
  %"@x_key" = alloca i64, align 8
  %"$kv" = alloca %"string[4]_string[4]__tuple_t", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$kv")
  call void @llvm.memset.p0.i64(ptr align 1 %"$kv", i8 0, i64 8, i1 false)
  %5 = getelementptr %"string[4]_string[4]__tuple_t", ptr %"$kv", i32 0, i32 0
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %5, ptr align 1 %1, i64 4, i1 false)
  %6 = getelementptr %"string[4]_string[4]__tuple_t", ptr %"$kv", i32 0, i32 1
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %6, ptr align 1 %2, i64 4, i1 false)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key")
  store i64 0, ptr %"@x_key", align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %"@x_key", ptr %"$kv", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key")
  ret i64 0
}

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: readwrite)
declare void @llvm.memcpy.p0.p0.i64(ptr noalias nocapture writeonly %0, ptr noalias nocapture readonly %1, i64 %2, i1 immarg %3) #3

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #2 = { nocallback nofree nounwind willreturn memory(argmem: write) }
attributes #3 = { nocallback nofree nounwind willreturn memory(argmem: readwrite) }

!llvm.dbg.cu = !{!64}
!llvm.module.flags = !{!66}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "AT_map", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !4)
!4 = !{!5, !11, !16, !22}
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
!18 = !DICompositeType(tag: DW_TAG_array_type, baseType: !19, size: 32, elements: !20)
!19 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!20 = !{!21}
!21 = !DISubrange(count: 4, lowerBound: 0)
!22 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !17, size: 64, offset: 192)
!23 = !DIGlobalVariableExpression(var: !24, expr: !DIExpression())
!24 = distinct !DIGlobalVariable(name: "AT_x", linkageName: "global", scope: !2, file: !2, type: !25, isLocal: false, isDefinition: true)
!25 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !26)
!26 = !{!5, !11, !27, !30}
!27 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !28, size: 64, offset: 128)
!28 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !29, size: 64)
!29 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!30 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !31, size: 64, offset: 192)
!31 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !32, size: 64)
!32 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 64, elements: !33)
!33 = !{!34, !35}
!34 = !DIDerivedType(tag: DW_TAG_member, scope: !2, file: !2, baseType: !18, size: 32)
!35 = !DIDerivedType(tag: DW_TAG_member, scope: !2, file: !2, baseType: !18, size: 32, offset: 32)
!36 = !DIGlobalVariableExpression(var: !37, expr: !DIExpression())
!37 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !38, isLocal: false, isDefinition: true)
!38 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !39)
!39 = !{!40, !45}
!40 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !41, size: 64)
!41 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !42, size: 64)
!42 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !43)
!43 = !{!44}
!44 = !DISubrange(count: 27, lowerBound: 0)
!45 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !46, size: 64, offset: 64)
!46 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !47, size: 64)
!47 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !48)
!48 = !{!49}
!49 = !DISubrange(count: 262144, lowerBound: 0)
!50 = !DIGlobalVariableExpression(var: !51, expr: !DIExpression())
!51 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !52, isLocal: false, isDefinition: true)
!52 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !53)
!53 = !{!54, !59, !60, !63}
!54 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !55, size: 64)
!55 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !56, size: 64)
!56 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !57)
!57 = !{!58}
!58 = !DISubrange(count: 2, lowerBound: 0)
!59 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !6, size: 64, offset: 64)
!60 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !61, size: 64, offset: 128)
!61 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !62, size: 64)
!62 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!63 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !28, size: 64, offset: 192)
!64 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !65)
!65 = !{!0, !23, !36, !50}
!66 = !{i32 2, !"Debug Info Version", i32 3}
!67 = distinct !DISubprogram(name: "BEGIN_1", linkageName: "BEGIN_1", scope: !2, file: !2, type: !68, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !64, retainedNodes: !71)
!68 = !DISubroutineType(types: !69)
!69 = !{!29, !70}
!70 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !19, size: 64)
!71 = !{!72}
!72 = !DILocalVariable(name: "ctx", arg: 1, scope: !67, file: !2, type: !70)
!73 = distinct !DISubprogram(name: "map_for_each_cb", linkageName: "map_for_each_cb", scope: !2, file: !2, type: !68, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !64, retainedNodes: !74)
!74 = !{!75}
!75 = !DILocalVariable(name: "ctx", arg: 1, scope: !73, file: !2, type: !70)
