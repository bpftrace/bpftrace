; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { i8*, i8*, i8*, i8* }
%"struct map_t.0" = type { i8*, i8* }
%"struct map_t.1" = type { i8*, i8*, i8*, i8* }
%ctx_t.2 = type { i64*, i64* }
%ctx_t = type { i64* }
%"unsigned int64_int64__tuple_t" = type { i64, i64 }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_ = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@ringbuf = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !20
@event_loss_counter = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !34

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @BEGIN_1(i8* %0) section "s_BEGIN_1" !dbg !51 {
entry:
  %ctx1 = alloca %ctx_t.2, align 8
  %ctx = alloca %ctx_t, align 8
  %"$var2" = alloca i64, align 8
  %1 = bitcast i64* %"$var2" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 0, i64* %"$var2", align 8
  %"$var1" = alloca i64, align 8
  %2 = bitcast i64* %"$var1" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %2)
  store i64 0, i64* %"$var1", align 8
  %"@_val" = alloca i64, align 8
  %"@_key" = alloca i64, align 8
  %3 = bitcast i64* %"@_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %3)
  store i64 0, i64* %"@_key", align 8
  %4 = bitcast i64* %"@_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %4)
  store i64 0, i64* %"@_val", align 8
  %update_elem = call i64 inttoptr (i64 2 to i64 (%"struct map_t"*, i64*, i64*, i64)*)(%"struct map_t"* @AT_, i64* %"@_key", i64* %"@_val", i64 0)
  %5 = bitcast i64* %"@_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %5)
  %6 = bitcast i64* %"@_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %6)
  store i64 0, i64* %"$var1", align 8
  store i64 0, i64* %"$var2", align 8
  %7 = bitcast %ctx_t* %ctx to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %7)
  %"ctx.$var1" = getelementptr %ctx_t, %ctx_t* %ctx, i64 0, i32 0
  store i64* %"$var1", i64** %"ctx.$var1", align 8
  %8 = bitcast %ctx_t* %ctx to i8*
  %for_each_map_elem = call i64 inttoptr (i64 164 to i64 (%"struct map_t"*, i64 (i8*, i8*, i8*, %ctx_t*)*, i8*, i64)*)(%"struct map_t"* @AT_, i64 (i8*, i8*, i8*, %ctx_t*)* @map_for_each_cb, i8* %8, i64 0)
  %9 = bitcast %ctx_t.2* %ctx1 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %9)
  %"ctx.$var12" = getelementptr %ctx_t.2, %ctx_t.2* %ctx1, i64 0, i32 0
  store i64* %"$var1", i64** %"ctx.$var12", align 8
  %"ctx.$var2" = getelementptr %ctx_t.2, %ctx_t.2* %ctx1, i64 0, i32 1
  store i64* %"$var2", i64** %"ctx.$var2", align 8
  %10 = bitcast %ctx_t.2* %ctx1 to i8*
  %for_each_map_elem3 = call i64 inttoptr (i64 164 to i64 (%"struct map_t"*, i64 (i8*, i8*, i8*, %ctx_t.2*)*, i8*, i64)*)(%"struct map_t"* @AT_, i64 (i8*, i8*, i8*, %ctx_t.2*)* @map_for_each_cb.1, i8* %10, i64 0)
  ret i64 0
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

define internal i64 @map_for_each_cb(i8* %0, i8* %1, i8* %2, %ctx_t* %3) section ".text" !dbg !58 {
  %"$_" = alloca %"unsigned int64_int64__tuple_t", align 8
  %key = load i64, i8* %1, align 8
  %val = load i64, i8* %2, align 8
  %5 = bitcast %"unsigned int64_int64__tuple_t"* %"$_" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %5)
  %6 = bitcast %"unsigned int64_int64__tuple_t"* %"$_" to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %6, i8 0, i64 16, i1 false)
  %7 = getelementptr %"unsigned int64_int64__tuple_t", %"unsigned int64_int64__tuple_t"* %"$_", i32 0, i32 0
  store i64 %key, i64* %7, align 8
  %8 = getelementptr %"unsigned int64_int64__tuple_t", %"unsigned int64_int64__tuple_t"* %"$_", i32 0, i32 1
  store i64 %val, i64* %8, align 8
  %"ctx.$var1" = getelementptr %ctx_t, %ctx_t* %3, i64 0, i32 0
  %"$var1" = load i64*, i64** %"ctx.$var1", align 8
  %9 = load i64, i64* %"$var1", align 8
  %10 = add i64 %9, 1
  store i64 %10, i64* %"$var1", align 8
  ret i64 0
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn writeonly
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

define internal i64 @map_for_each_cb.1(i8* %0, i8* %1, i8* %2, %ctx_t.2* %3) section ".text" !dbg !61 {
  %"$_" = alloca %"unsigned int64_int64__tuple_t", align 8
  %key = load i64, i8* %1, align 8
  %val = load i64, i8* %2, align 8
  %5 = bitcast %"unsigned int64_int64__tuple_t"* %"$_" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %5)
  %6 = bitcast %"unsigned int64_int64__tuple_t"* %"$_" to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %6, i8 0, i64 16, i1 false)
  %7 = getelementptr %"unsigned int64_int64__tuple_t", %"unsigned int64_int64__tuple_t"* %"$_", i32 0, i32 0
  store i64 %key, i64* %7, align 8
  %8 = getelementptr %"unsigned int64_int64__tuple_t", %"unsigned int64_int64__tuple_t"* %"$_", i32 0, i32 1
  store i64 %val, i64* %8, align 8
  %"ctx.$var1" = getelementptr %ctx_t.2, %ctx_t.2* %3, i64 0, i32 0
  %"$var1" = load i64*, i64** %"ctx.$var1", align 8
  %"ctx.$var2" = getelementptr %ctx_t.2, %ctx_t.2* %3, i64 0, i32 1
  %"$var2" = load i64*, i64** %"ctx.$var2", align 8
  %9 = load i64, i64* %"$var1", align 8
  %10 = add i64 %9, 1
  store i64 %10, i64* %"$var1", align 8
  %11 = load i64, i64* %"$var2", align 8
  %12 = add i64 %11, 1
  store i64 %12, i64* %"$var2", align 8
  ret i64 0
}

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }
attributes #2 = { argmemonly nofree nosync nounwind willreturn writeonly }

!llvm.dbg.cu = !{!47}
!llvm.module.flags = !{!50}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "AT_", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
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
!47 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, enums: !48, globals: !49)
!48 = !{}
!49 = !{!0, !20, !34}
!50 = !{i32 2, !"Debug Info Version", i32 3}
!51 = distinct !DISubprogram(name: "BEGIN_1", linkageName: "BEGIN_1", scope: !2, file: !2, type: !52, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !47, retainedNodes: !56)
!52 = !DISubroutineType(types: !53)
!53 = !{!18, !54}
!54 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !55, size: 64)
!55 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!56 = !{!57}
!57 = !DILocalVariable(name: "ctx", arg: 1, scope: !51, file: !2, type: !54)
!58 = distinct !DISubprogram(name: "map_for_each_cb", linkageName: "map_for_each_cb", scope: !2, file: !2, type: !52, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !47, retainedNodes: !59)
!59 = !{!60}
!60 = !DILocalVariable(name: "ctx", arg: 1, scope: !58, file: !2, type: !54)
!61 = distinct !DISubprogram(name: "map_for_each_cb_1", linkageName: "map_for_each_cb_1", scope: !2, file: !2, type: !52, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !47, retainedNodes: !62)
!62 = !{!63}
!63 = !DILocalVariable(name: "ctx", arg: 1, scope: !61, file: !2, type: !54)
