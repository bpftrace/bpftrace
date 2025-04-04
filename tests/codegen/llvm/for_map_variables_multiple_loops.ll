; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr }
%"struct map_t.1" = type { ptr, ptr, ptr, ptr }
%ctx_t.2 = type { ptr, ptr }
%ctx_t = type { ptr }
%int64_int64__tuple_t = type { i64, i64 }

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@AT_ = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !7
@ringbuf = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !22
@event_loss_counter = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !36

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @BEGIN_1(ptr %0) section "s_BEGIN_1" !dbg !51 {
entry:
  %ctx1 = alloca %ctx_t.2, align 8
  %ctx = alloca %ctx_t, align 8
  %"$var2" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$var2")
  store i64 0, ptr %"$var2", align 8
  %"$var1" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$var1")
  store i64 0, ptr %"$var1", align 8
  %"@_val" = alloca i64, align 8
  %"@_key" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@_key")
  store i64 0, ptr %"@_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@_val")
  store i64 0, ptr %"@_val", align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_, ptr %"@_key", ptr %"@_val", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@_key")
  store i64 0, ptr %"$var1", align 8
  store i64 0, ptr %"$var2", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %ctx)
  %1 = call ptr @llvm.preserve.static.offset(ptr %ctx)
  %"ctx.$var1" = getelementptr %ctx_t, ptr %1, i64 0, i32 0
  store ptr %"$var1", ptr %"ctx.$var1", align 8
  %for_each_map_elem = call i64 inttoptr (i64 164 to ptr)(ptr @AT_, ptr @map_for_each_cb, ptr %ctx, i64 0)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %ctx1)
  %2 = call ptr @llvm.preserve.static.offset(ptr %ctx1)
  %"ctx.$var12" = getelementptr %ctx_t.2, ptr %2, i64 0, i32 0
  store ptr %"$var1", ptr %"ctx.$var12", align 8
  %3 = call ptr @llvm.preserve.static.offset(ptr %ctx1)
  %"ctx.$var2" = getelementptr %ctx_t.2, ptr %3, i64 0, i32 1
  store ptr %"$var2", ptr %"ctx.$var2", align 8
  %for_each_map_elem3 = call i64 inttoptr (i64 164 to ptr)(ptr @AT_, ptr @map_for_each_cb.1, ptr %ctx1, i64 0)
  ret i64 0
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare ptr @llvm.preserve.static.offset(ptr readnone %0) #2

define internal i64 @map_for_each_cb(ptr %0, ptr %1, ptr %2, ptr %3) section ".text" !dbg !57 {
  %"$_" = alloca %int64_int64__tuple_t, align 8
  %key = load i64, ptr %1, align 8
  %val = load i64, ptr %2, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$_")
  call void @llvm.memset.p0.i64(ptr align 1 %"$_", i8 0, i64 16, i1 false)
  %5 = getelementptr %int64_int64__tuple_t, ptr %"$_", i32 0, i32 0
  store i64 %key, ptr %5, align 8
  %6 = getelementptr %int64_int64__tuple_t, ptr %"$_", i32 0, i32 1
  store i64 %val, ptr %6, align 8
  %"ctx.$var1" = getelementptr %ctx_t, ptr %3, i64 0, i32 0
  %"$var1" = load ptr, ptr %"ctx.$var1", align 8
  %7 = load i64, ptr %"$var1", align 8
  %8 = add i64 %7, 1
  store i64 %8, ptr %"$var1", align 8
  ret i64 0
}

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #3

define internal i64 @map_for_each_cb.1(ptr %0, ptr %1, ptr %2, ptr %3) section ".text" !dbg !65 {
  %"$_" = alloca %int64_int64__tuple_t, align 8
  %key = load i64, ptr %1, align 8
  %val = load i64, ptr %2, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$_")
  call void @llvm.memset.p0.i64(ptr align 1 %"$_", i8 0, i64 16, i1 false)
  %5 = getelementptr %int64_int64__tuple_t, ptr %"$_", i32 0, i32 0
  store i64 %key, ptr %5, align 8
  %6 = getelementptr %int64_int64__tuple_t, ptr %"$_", i32 0, i32 1
  store i64 %val, ptr %6, align 8
  %"ctx.$var1" = getelementptr %ctx_t.2, ptr %3, i64 0, i32 0
  %"$var1" = load ptr, ptr %"ctx.$var1", align 8
  %"ctx.$var2" = getelementptr %ctx_t.2, ptr %3, i64 0, i32 1
  %"$var2" = load ptr, ptr %"ctx.$var2", align 8
  %7 = load i64, ptr %"$var1", align 8
  %8 = add i64 %7, 1
  store i64 %8, ptr %"$var1", align 8
  %9 = load i64, ptr %"$var2", align 8
  %10 = add i64 %9, 1
  store i64 %10, ptr %"$var2", align 8
  ret i64 0
}

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #2 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }
attributes #3 = { nocallback nofree nounwind willreturn memory(argmem: write) }

!llvm.dbg.cu = !{!48}
!llvm.module.flags = !{!50}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "LICENSE", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 32, elements: !5)
!4 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!5 = !{!6}
!6 = !DISubrange(count: 4, lowerBound: 0)
!7 = !DIGlobalVariableExpression(var: !8, expr: !DIExpression())
!8 = distinct !DIGlobalVariable(name: "AT_", linkageName: "global", scope: !2, file: !2, type: !9, isLocal: false, isDefinition: true)
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
!23 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !24, isLocal: false, isDefinition: true)
!24 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !25)
!25 = !{!26, !31}
!26 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !27, size: 64)
!27 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !28, size: 64)
!28 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 864, elements: !29)
!29 = !{!30}
!30 = !DISubrange(count: 27, lowerBound: 0)
!31 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !32, size: 64, offset: 64)
!32 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !33, size: 64)
!33 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 8388608, elements: !34)
!34 = !{!35}
!35 = !DISubrange(count: 262144, lowerBound: 0)
!36 = !DIGlobalVariableExpression(var: !37, expr: !DIExpression())
!37 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !38, isLocal: false, isDefinition: true)
!38 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !39)
!39 = !{!40, !17, !45, !21}
!40 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !41, size: 64)
!41 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !42, size: 64)
!42 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 64, elements: !43)
!43 = !{!44}
!44 = !DISubrange(count: 2, lowerBound: 0)
!45 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !46, size: 64, offset: 128)
!46 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !47, size: 64)
!47 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!48 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !49)
!49 = !{!0, !7, !22, !36}
!50 = !{i32 2, !"Debug Info Version", i32 3}
!51 = distinct !DISubprogram(name: "BEGIN_1", linkageName: "BEGIN_1", scope: !2, file: !2, type: !52, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !48, retainedNodes: !55)
!52 = !DISubroutineType(types: !53)
!53 = !{!20, !54}
!54 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!55 = !{!56}
!56 = !DILocalVariable(name: "ctx", arg: 1, scope: !51, file: !2, type: !54)
!57 = distinct !DISubprogram(name: "map_for_each_cb", linkageName: "map_for_each_cb", scope: !2, file: !2, type: !58, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !48, retainedNodes: !60)
!58 = !DISubroutineType(types: !59)
!59 = !{!20, !54, !54, !54, !54}
!60 = !{!61, !62, !63, !64}
!61 = !DILocalVariable(name: "map", arg: 1, scope: !57, file: !2, type: !54)
!62 = !DILocalVariable(name: "key", arg: 2, scope: !57, file: !2, type: !54)
!63 = !DILocalVariable(name: "value", arg: 3, scope: !57, file: !2, type: !54)
!64 = !DILocalVariable(name: "ctx", arg: 4, scope: !57, file: !2, type: !54)
!65 = distinct !DISubprogram(name: "map_for_each_cb_1", linkageName: "map_for_each_cb_1", scope: !2, file: !2, type: !58, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !48, retainedNodes: !66)
!66 = !{!67, !68, !69, !70}
!67 = !DILocalVariable(name: "map", arg: 1, scope: !65, file: !2, type: !54)
!68 = !DILocalVariable(name: "key", arg: 2, scope: !65, file: !2, type: !54)
!69 = !DILocalVariable(name: "value", arg: 3, scope: !65, file: !2, type: !54)
!70 = !DILocalVariable(name: "ctx", arg: 4, scope: !65, file: !2, type: !54)
