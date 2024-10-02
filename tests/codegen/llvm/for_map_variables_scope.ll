; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr }
%"struct map_t.1" = type { ptr, ptr, ptr, ptr }
%int64_int64__tuple_t = type { i64, i64 }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_map = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@ringbuf = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !20
@event_loss_counter = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !34
@max_cpu_id = dso_local externally_initialized constant i64 zeroinitializer, section ".rodata", !dbg !47
@tuple_buf = dso_local externally_initialized global [1 x [2 x [16 x i8]]] zeroinitializer, section ".data.tuple_buf", !dbg !49

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @BEGIN_1(ptr %0) section "s_BEGIN_1" !dbg !60 {
entry:
  %"@map_val" = alloca i64, align 8
  %"@map_key" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@map_key")
  store i64 16, ptr %"@map_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@map_val")
  store i64 32, ptr %"@map_val", align 8
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

define internal i64 @map_for_each_cb(ptr %0, ptr %1, ptr %2, ptr %3) section ".text" !dbg !66 {
  %"$var" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$var")
  store i64 0, ptr %"$var", align 8
  %key = load i64, ptr %1, align 8
  %val = load i64, ptr %2, align 8
  %get_cpu_id = call i64 inttoptr (i64 8 to ptr)()
  %5 = load i64, ptr @max_cpu_id, align 8
  %cpuid.min.cmp = icmp ule i64 %get_cpu_id, %5
  %cpuid.min.select = select i1 %cpuid.min.cmp, i64 %get_cpu_id, i64 %5
  %6 = getelementptr [1 x [2 x [16 x i8]]], ptr @tuple_buf, i64 0, i64 %cpuid.min.select, i64 0, i64 0
  call void @llvm.memset.p0.i64(ptr align 1 %6, i8 0, i64 16, i1 false)
  %7 = getelementptr %int64_int64__tuple_t, ptr %6, i32 0, i32 0
  store i64 %key, ptr %7, align 8
  %8 = getelementptr %int64_int64__tuple_t, ptr %6, i32 0, i32 1
  store i64 %val, ptr %8, align 8
  store i64 1, ptr %"$var", align 8
  ret i64 0
}

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

define internal i64 @map_for_each_cb.1(ptr %0, ptr %1, ptr %2, ptr %3) section ".text" !dbg !69 {
  %"$var" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$var")
  store i64 0, ptr %"$var", align 8
  %key = load i64, ptr %1, align 8
  %val = load i64, ptr %2, align 8
  %get_cpu_id = call i64 inttoptr (i64 8 to ptr)()
  %5 = load i64, ptr @max_cpu_id, align 8
  %cpuid.min.cmp = icmp ule i64 %get_cpu_id, %5
  %cpuid.min.select = select i1 %cpuid.min.cmp, i64 %get_cpu_id, i64 %5
  %6 = getelementptr [1 x [2 x [16 x i8]]], ptr @tuple_buf, i64 0, i64 %cpuid.min.select, i64 1, i64 0
  call void @llvm.memset.p0.i64(ptr align 1 %6, i8 0, i64 16, i1 false)
  %7 = getelementptr %int64_int64__tuple_t, ptr %6, i32 0, i32 0
  store i64 %key, ptr %7, align 8
  %8 = getelementptr %int64_int64__tuple_t, ptr %6, i32 0, i32 1
  store i64 %val, ptr %8, align 8
  store i64 1, ptr %"$var", align 8
  ret i64 0
}

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #2 = { nocallback nofree nounwind willreturn memory(argmem: write) }

!llvm.dbg.cu = !{!57}
!llvm.module.flags = !{!59}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "AT_map", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !4)
!4 = !{!5, !11, !16, !19}
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
!18 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!19 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !17, size: 64, offset: 192)
!20 = !DIGlobalVariableExpression(var: !21, expr: !DIExpression())
!21 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !22, isLocal: false, isDefinition: true)
!22 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !23)
!23 = !{!24, !29}
!24 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !25, size: 64)
!25 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !26, size: 64)
!26 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !27)
!27 = !{!28}
!28 = !DISubrange(count: 27, lowerBound: 0)
!29 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !30, size: 64, offset: 64)
!30 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !31, size: 64)
!31 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !32)
!32 = !{!33}
!33 = !DISubrange(count: 262144, lowerBound: 0)
!34 = !DIGlobalVariableExpression(var: !35, expr: !DIExpression())
!35 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !36, isLocal: false, isDefinition: true)
!36 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !37)
!37 = !{!38, !43, !44, !19}
!38 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !39, size: 64)
!39 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !40, size: 64)
!40 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !41)
!41 = !{!42}
!42 = !DISubrange(count: 2, lowerBound: 0)
!43 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !6, size: 64, offset: 64)
!44 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !45, size: 64, offset: 128)
!45 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !46, size: 64)
!46 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!47 = !DIGlobalVariableExpression(var: !48, expr: !DIExpression())
!48 = distinct !DIGlobalVariable(name: "max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !18, isLocal: false, isDefinition: true)
!49 = !DIGlobalVariableExpression(var: !50, expr: !DIExpression())
!50 = distinct !DIGlobalVariable(name: "tuple_buf", linkageName: "global", scope: !2, file: !2, type: !51, isLocal: false, isDefinition: true)
!51 = !DICompositeType(tag: DW_TAG_array_type, baseType: !52, size: 256, elements: !9)
!52 = !DICompositeType(tag: DW_TAG_array_type, baseType: !53, size: 256, elements: !41)
!53 = !DICompositeType(tag: DW_TAG_array_type, baseType: !54, size: 128, elements: !55)
!54 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!55 = !{!56}
!56 = !DISubrange(count: 16, lowerBound: 0)
!57 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !58)
!58 = !{!0, !20, !34, !47, !49}
!59 = !{i32 2, !"Debug Info Version", i32 3}
!60 = distinct !DISubprogram(name: "BEGIN_1", linkageName: "BEGIN_1", scope: !2, file: !2, type: !61, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !57, retainedNodes: !64)
!61 = !DISubroutineType(types: !62)
!62 = !{!18, !63}
!63 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !54, size: 64)
!64 = !{!65}
!65 = !DILocalVariable(name: "ctx", arg: 1, scope: !60, file: !2, type: !63)
!66 = distinct !DISubprogram(name: "map_for_each_cb", linkageName: "map_for_each_cb", scope: !2, file: !2, type: !61, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !57, retainedNodes: !67)
!67 = !{!68}
!68 = !DILocalVariable(name: "ctx", arg: 1, scope: !66, file: !2, type: !63)
!69 = distinct !DISubprogram(name: "map_for_each_cb_1", linkageName: "map_for_each_cb_1", scope: !2, file: !2, type: !61, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !57, retainedNodes: !70)
!70 = !{!71}
!71 = !DILocalVariable(name: "ctx", arg: 1, scope: !69, file: !2, type: !63)
