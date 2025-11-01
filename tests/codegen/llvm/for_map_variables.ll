; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%"struct map_internal_repr_t" = type { ptr, ptr, ptr, ptr }
%"struct map_internal_repr_t.616" = type { ptr, ptr, ptr, ptr }
%"struct map_internal_repr_t.617" = type { ptr, ptr }
%ctx_t = type { ptr, ptr }
%uint8_uint8__tuple_t = type { i8, i8 }

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@AT_len = dso_local global %"struct map_internal_repr_t" zeroinitializer, section ".maps", !dbg !7
@AT_map = dso_local global %"struct map_internal_repr_t.616" zeroinitializer, section ".maps", !dbg !22
@ringbuf = dso_local global %"struct map_internal_repr_t.617" zeroinitializer, section ".maps", !dbg !34
@__bt__event_loss_counter = dso_local externally_initialized global [1 x [1 x i64]] zeroinitializer, section ".data.event_loss_counter", !dbg !48
@__bt__max_cpu_id = dso_local externally_initialized constant i64 0, section ".rodata", !dbg !52
@abc = global [4 x i8] c"abc\00"
@def = global [4 x i8] c"def\00"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

; Function Attrs: nounwind
define i64 @begin_1(ptr %0) #0 section "s_begin_1" !dbg !58 {
entry:
  %"@len_val" = alloca i64, align 8
  %"@len_key" = alloca i64, align 8
  %ctx = alloca %ctx_t, align 8
  %"$var3" = alloca [4 x i8], align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$var3")
  call void @llvm.memset.p0.i64(ptr align 1 %"$var3", i8 0, i64 4, i1 false)
  %"$var2" = alloca [4 x i8], align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$var2")
  call void @llvm.memset.p0.i64(ptr align 1 %"$var2", i8 0, i64 4, i1 false)
  %"$var1" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$var1")
  store i64 0, ptr %"$var1", align 8
  %"@map_val" = alloca i8, align 1
  %"@map_key" = alloca i8, align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@map_key")
  store i8 16, ptr %"@map_key", align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@map_val")
  store i8 32, ptr %"@map_val", align 1
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_map, ptr %"@map_key", ptr %"@map_val", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@map_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@map_key")
  store i64 123, ptr %"$var1", align 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %"$var2", ptr align 1 @abc, i64 4, i1 false)
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %"$var3", ptr align 1 @def, i64 4, i1 false)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %ctx)
  %1 = call ptr @llvm.preserve.static.offset(ptr %ctx)
  %"ctx.$var1" = getelementptr %ctx_t, ptr %1, i64 0, i32 0
  store ptr %"$var1", ptr %"ctx.$var1", align 8
  %2 = call ptr @llvm.preserve.static.offset(ptr %ctx)
  %"ctx.$var3" = getelementptr %ctx_t, ptr %2, i64 0, i32 1
  store ptr %"$var3", ptr %"ctx.$var3", align 8
  %for_each_map_elem = call i64 inttoptr (i64 164 to ptr)(ptr @AT_map, ptr @map_for_each_cb, ptr %ctx, i64 0)
  %3 = load i64, ptr %"$var1", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@len_key")
  store i64 0, ptr %"@len_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@len_val")
  store i64 %3, ptr %"@len_val", align 8
  %update_elem1 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_len, ptr %"@len_key", ptr %"@len_val", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@len_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@len_key")
  ret i64 0
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: readwrite)
declare void @llvm.memcpy.p0.p0.i64(ptr noalias nocapture writeonly %0, ptr noalias nocapture readonly %1, i64 %2, i1 immarg %3) #3

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare ptr @llvm.preserve.static.offset(ptr readnone %0) #4

; Function Attrs: nounwind
define internal i64 @map_for_each_cb(ptr %0, ptr %1, ptr %2, ptr %3) #0 section ".text" !dbg !63 {
for_body:
  %"$can_read" = alloca [4 x i8], align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$can_read")
  call void @llvm.memset.p0.i64(ptr align 1 %"$can_read", i8 0, i64 4, i1 false)
  %"$kv" = alloca %uint8_uint8__tuple_t, align 8
  %key = load i8, ptr %1, align 1
  %val = load i8, ptr %2, align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$kv")
  call void @llvm.memset.p0.i64(ptr align 1 %"$kv", i8 0, i64 2, i1 false)
  %4 = getelementptr %uint8_uint8__tuple_t, ptr %"$kv", i32 0, i32 0
  store i8 %key, ptr %4, align 1
  %5 = getelementptr %uint8_uint8__tuple_t, ptr %"$kv", i32 0, i32 1
  store i8 %val, ptr %5, align 1
  %"ctx.$var1" = getelementptr %ctx_t, ptr %3, i64 0, i32 0
  %"$var1" = load ptr, ptr %"ctx.$var1", align 8
  %"ctx.$var3" = getelementptr %ctx_t, ptr %3, i64 0, i32 1
  %"$var3" = load ptr, ptr %"ctx.$var3", align 8
  %6 = load i64, ptr %"$var1", align 8
  %7 = add i64 %6, 1
  store i64 %7, ptr %"$var1", align 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %"$can_read", ptr align 1 %"$var3", i64 4, i1 false)
  br label %for_continue

for_continue:                                     ; preds = %for_body
  ret i64 0
}

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #2 = { nocallback nofree nounwind willreturn memory(argmem: write) }
attributes #3 = { nocallback nofree nounwind willreturn memory(argmem: readwrite) }
attributes #4 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }

!llvm.dbg.cu = !{!54}
!llvm.module.flags = !{!56, !57}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "LICENSE", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 32, elements: !5)
!4 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!5 = !{!6}
!6 = !DISubrange(count: 4, lowerBound: 0)
!7 = !DIGlobalVariableExpression(var: !8, expr: !DIExpression())
!8 = distinct !DIGlobalVariable(name: "AT_len", linkageName: "global", scope: !2, file: !2, type: !9, isLocal: false, isDefinition: true)
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
!21 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !19, size: 64, offset: 192)
!22 = !DIGlobalVariableExpression(var: !23, expr: !DIExpression())
!23 = distinct !DIGlobalVariable(name: "AT_map", linkageName: "global", scope: !2, file: !2, type: !24, isLocal: false, isDefinition: true)
!24 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !25)
!25 = !{!11, !26, !31, !33}
!26 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !27, size: 64, offset: 64)
!27 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !28, size: 64)
!28 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 131072, elements: !29)
!29 = !{!30}
!30 = !DISubrange(count: 4096, lowerBound: 0)
!31 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !32, size: 64, offset: 128)
!32 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!33 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !32, size: 64, offset: 192)
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
!49 = distinct !DIGlobalVariable(name: "__bt__event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !50, isLocal: false, isDefinition: true)
!50 = !DICompositeType(tag: DW_TAG_array_type, baseType: !51, size: 64, elements: !15)
!51 = !DICompositeType(tag: DW_TAG_array_type, baseType: !20, size: 64, elements: !15)
!52 = !DIGlobalVariableExpression(var: !53, expr: !DIExpression())
!53 = distinct !DIGlobalVariable(name: "__bt__max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !20, isLocal: false, isDefinition: true)
!54 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !55)
!55 = !{!0, !7, !22, !34, !48, !52}
!56 = !{i32 2, !"Debug Info Version", i32 3}
!57 = !{i32 7, !"uwtable", i32 0}
!58 = distinct !DISubprogram(name: "begin_1", linkageName: "begin_1", scope: !2, file: !2, type: !59, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !54, retainedNodes: !61)
!59 = !DISubroutineType(types: !60)
!60 = !{!20, !32}
!61 = !{!62}
!62 = !DILocalVariable(name: "ctx", arg: 1, scope: !58, file: !2, type: !32)
!63 = distinct !DISubprogram(name: "map_for_each_cb", linkageName: "map_for_each_cb", scope: !2, file: !2, type: !64, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !54, retainedNodes: !66)
!64 = !DISubroutineType(types: !65)
!65 = !{!20, !32, !32, !32, !32}
!66 = !{!67, !68, !69, !70}
!67 = !DILocalVariable(name: "map", arg: 1, scope: !63, file: !2, type: !32)
!68 = !DILocalVariable(name: "key", arg: 2, scope: !63, file: !2, type: !32)
!69 = !DILocalVariable(name: "value", arg: 3, scope: !63, file: !2, type: !32)
!70 = !DILocalVariable(name: "ctx", arg: 4, scope: !63, file: !2, type: !32)
