; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { i8*, i8*, i8*, i8* }
%"struct map_t.0" = type { i8*, i8*, i8*, i8* }
%"struct map_t.1" = type { i8*, i8* }
%"struct map_t.2" = type { i8*, i8*, i8*, i8* }
%"(unsigned int64,unsigned int64)_int64__tuple_t" = type { %"unsigned int64_unsigned int64__tuple_t", i64 }
%"unsigned int64_unsigned int64__tuple_t" = type { i64, i64 }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_map = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@AT_x = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !25
@ringbuf = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !40
@event_loss_counter = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !54

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @BEGIN_1(i8* %0) section "s_BEGIN_1" !dbg !71 {
entry:
  %"@map_val" = alloca i64, align 8
  %"@map_key" = alloca [16 x i8], align 1
  %1 = bitcast [16 x i8]* %"@map_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  %2 = getelementptr [16 x i8], [16 x i8]* %"@map_key", i64 0, i64 0
  %3 = bitcast i8* %2 to i64*
  store i64 16, i64* %3, align 8
  %4 = getelementptr [16 x i8], [16 x i8]* %"@map_key", i64 0, i64 8
  %5 = bitcast i8* %4 to i64*
  store i64 17, i64* %5, align 8
  %6 = bitcast i64* %"@map_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %6)
  store i64 32, i64* %"@map_val", align 8
  %update_elem = call i64 inttoptr (i64 2 to i64 (%"struct map_t"*, [16 x i8]*, i64*, i64)*)(%"struct map_t"* @AT_map, [16 x i8]* %"@map_key", i64* %"@map_val", i64 0)
  %7 = bitcast i64* %"@map_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %7)
  %8 = bitcast [16 x i8]* %"@map_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %8)
  %for_each_map_elem = call i64 inttoptr (i64 164 to i64 (%"struct map_t"*, i64 (i8*, i8*, i8*, i8*)*, i8*, i64)*)(%"struct map_t"* @AT_map, i64 (i8*, i8*, i8*, i8*)* @map_for_each_cb, i8* null, i64 0)
  ret i64 0
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

define internal i64 @map_for_each_cb(i8* %0, i8* %1, i8* %2, i8* %3) section ".text" !dbg !77 {
  %"@x_key" = alloca i64, align 8
  %"$kv" = alloca %"(unsigned int64,unsigned int64)_int64__tuple_t", align 8
  %val = load i64, i8* %2, align 8
  %5 = bitcast %"(unsigned int64,unsigned int64)_int64__tuple_t"* %"$kv" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %5)
  %6 = bitcast %"(unsigned int64,unsigned int64)_int64__tuple_t"* %"$kv" to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %6, i8 0, i64 24, i1 false)
  %7 = getelementptr %"(unsigned int64,unsigned int64)_int64__tuple_t", %"(unsigned int64,unsigned int64)_int64__tuple_t"* %"$kv", i32 0, i32 0
  %8 = bitcast %"unsigned int64_unsigned int64__tuple_t"* %7 to i8*
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* align 1 %8, i8* align 1 %1, i64 16, i1 false)
  %9 = getelementptr %"(unsigned int64,unsigned int64)_int64__tuple_t", %"(unsigned int64,unsigned int64)_int64__tuple_t"* %"$kv", i32 0, i32 1
  store i64 %val, i64* %9, align 8
  %10 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %10)
  store i64 0, i64* %"@x_key", align 8
  %update_elem = call i64 inttoptr (i64 2 to i64 (%"struct map_t.0"*, i64*, %"(unsigned int64,unsigned int64)_int64__tuple_t"*, i64)*)(%"struct map_t.0"* @AT_x, i64* %"@x_key", %"(unsigned int64,unsigned int64)_int64__tuple_t"* %"$kv", i64 0)
  %11 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %11)
  ret i64 0
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn writeonly
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.memcpy.p0i8.p0i8.i64(i8* noalias nocapture writeonly %0, i8* noalias nocapture readonly %1, i64 %2, i1 immarg %3) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }
attributes #2 = { argmemonly nofree nosync nounwind willreturn writeonly }

!llvm.dbg.cu = !{!67}
!llvm.module.flags = !{!70}

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
!18 = !DICompositeType(tag: DW_TAG_array_type, baseType: !19, size: 128, elements: !20)
!19 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!20 = !{!21}
!21 = !DISubrange(count: 16, lowerBound: 0)
!22 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !23, size: 64, offset: 192)
!23 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !24, size: 64)
!24 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!25 = !DIGlobalVariableExpression(var: !26, expr: !DIExpression())
!26 = distinct !DIGlobalVariable(name: "AT_x", linkageName: "global", scope: !2, file: !2, type: !27, isLocal: false, isDefinition: true)
!27 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !28)
!28 = !{!5, !11, !29, !30}
!29 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !23, size: 64, offset: 128)
!30 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !31, size: 64, offset: 192)
!31 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !32, size: 64)
!32 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 192, elements: !33)
!33 = !{!34, !39}
!34 = !DIDerivedType(tag: DW_TAG_member, scope: !2, file: !2, baseType: !35, size: 128)
!35 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !36)
!36 = !{!37, !38}
!37 = !DIDerivedType(tag: DW_TAG_member, scope: !2, file: !2, baseType: !24, size: 64)
!38 = !DIDerivedType(tag: DW_TAG_member, scope: !2, file: !2, baseType: !24, size: 64, offset: 64)
!39 = !DIDerivedType(tag: DW_TAG_member, scope: !2, file: !2, baseType: !24, size: 64, offset: 128)
!40 = !DIGlobalVariableExpression(var: !41, expr: !DIExpression())
!41 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !42, isLocal: false, isDefinition: true)
!42 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !43)
!43 = !{!44, !49}
!44 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !45, size: 64)
!45 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !46, size: 64)
!46 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !47)
!47 = !{!48}
!48 = !DISubrange(count: 27, lowerBound: 0)
!49 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !50, size: 64, offset: 64)
!50 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !51, size: 64)
!51 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !52)
!52 = !{!53}
!53 = !DISubrange(count: 262144, lowerBound: 0)
!54 = !DIGlobalVariableExpression(var: !55, expr: !DIExpression())
!55 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !56, isLocal: false, isDefinition: true)
!56 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !57)
!57 = !{!58, !63, !64, !22}
!58 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !59, size: 64)
!59 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !60, size: 64)
!60 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !61)
!61 = !{!62}
!62 = !DISubrange(count: 2, lowerBound: 0)
!63 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !6, size: 64, offset: 64)
!64 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !65, size: 64, offset: 128)
!65 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !66, size: 64)
!66 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!67 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, enums: !68, globals: !69)
!68 = !{}
!69 = !{!0, !25, !40, !54}
!70 = !{i32 2, !"Debug Info Version", i32 3}
!71 = distinct !DISubprogram(name: "BEGIN_1", linkageName: "BEGIN_1", scope: !2, file: !2, type: !72, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !67, retainedNodes: !75)
!72 = !DISubroutineType(types: !73)
!73 = !{!24, !74}
!74 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !19, size: 64)
!75 = !{!76}
!76 = !DILocalVariable(name: "ctx", arg: 1, scope: !71, file: !2, type: !74)
!77 = distinct !DISubprogram(name: "map_for_each_cb", linkageName: "map_for_each_cb", scope: !2, file: !2, type: !72, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !67, retainedNodes: !78)
!78 = !{!79}
!79 = !DILocalVariable(name: "ctx", arg: 1, scope: !77, file: !2, type: !74)
