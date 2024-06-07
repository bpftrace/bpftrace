; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { i8*, i8*, i8*, i8* }
%"struct map_t.0" = type { i8*, i8* }
%"struct map_t.1" = type { i8*, i8*, i8*, i8* }
%"unsigned int8_usym_int64__tuple_t" = type { i8, [24 x i8], i64 }
%usym_t = type { i64, i64, i64 }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_t = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@ringbuf = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !30
@event_loss_counter = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !44

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(i8* %0) section "s_kprobe_f_1" !dbg !62 {
entry:
  %"@t_key" = alloca i64, align 8
  %tuple = alloca %"unsigned int8_usym_int64__tuple_t", align 8
  %usym = alloca %usym_t, align 8
  %1 = bitcast i8* %0 to i64*
  %2 = getelementptr i64, i64* %1, i64 16
  %reg_ip = load volatile i64, i64* %2, align 8
  %3 = bitcast %usym_t* %usym to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %3)
  %get_pid_tgid = call i64 inttoptr (i64 14 to i64 ()*)()
  %4 = lshr i64 %get_pid_tgid, 32
  %5 = getelementptr %usym_t, %usym_t* %usym, i64 0, i32 0
  %6 = getelementptr %usym_t, %usym_t* %usym, i64 0, i32 1
  %7 = getelementptr %usym_t, %usym_t* %usym, i64 0, i32 2
  store i64 %reg_ip, i64* %5, align 8
  store i64 %4, i64* %6, align 8
  store i64 0, i64* %7, align 8
  %8 = bitcast %"unsigned int8_usym_int64__tuple_t"* %tuple to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %8)
  %9 = bitcast %"unsigned int8_usym_int64__tuple_t"* %tuple to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %9, i8 0, i64 40, i1 false)
  %10 = getelementptr %"unsigned int8_usym_int64__tuple_t", %"unsigned int8_usym_int64__tuple_t"* %tuple, i32 0, i32 0
  store i8 1, i8* %10, align 1
  %11 = getelementptr %"unsigned int8_usym_int64__tuple_t", %"unsigned int8_usym_int64__tuple_t"* %tuple, i32 0, i32 1
  %12 = bitcast [24 x i8]* %11 to i8*
  %13 = bitcast %usym_t* %usym to i8*
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* align 1 %12, i8* align 1 %13, i64 24, i1 false)
  %14 = getelementptr %"unsigned int8_usym_int64__tuple_t", %"unsigned int8_usym_int64__tuple_t"* %tuple, i32 0, i32 2
  store i64 10, i64* %14, align 8
  %15 = bitcast i64* %"@t_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %15)
  store i64 0, i64* %"@t_key", align 8
  %update_elem = call i64 inttoptr (i64 2 to i64 (%"struct map_t"*, i64*, %"unsigned int8_usym_int64__tuple_t"*, i64)*)(%"struct map_t"* @AT_t, i64* %"@t_key", %"unsigned int8_usym_int64__tuple_t"* %tuple, i64 0)
  %16 = bitcast i64* %"@t_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %16)
  %17 = bitcast %"unsigned int8_usym_int64__tuple_t"* %tuple to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %17)
  ret i64 0
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn writeonly
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.memcpy.p0i8.p0i8.i64(i8* noalias nocapture writeonly %0, i8* noalias nocapture readonly %1, i64 %2, i1 immarg %3) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }
attributes #2 = { argmemonly nofree nosync nounwind willreturn writeonly }

!llvm.dbg.cu = !{!58}
!llvm.module.flags = !{!61}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "AT_t", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
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
!19 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !20, size: 64, offset: 192)
!20 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !21, size: 64)
!21 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 320, elements: !22)
!22 = !{!23, !25, !29}
!23 = !DIDerivedType(tag: DW_TAG_member, scope: !2, file: !2, baseType: !24, size: 8)
!24 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!25 = !DIDerivedType(tag: DW_TAG_member, scope: !2, file: !2, baseType: !26, size: 192, offset: 8)
!26 = !DICompositeType(tag: DW_TAG_array_type, baseType: !24, size: 192, elements: !27)
!27 = !{!28}
!28 = !DISubrange(count: 24, lowerBound: 0)
!29 = !DIDerivedType(tag: DW_TAG_member, scope: !2, file: !2, baseType: !18, size: 64, offset: 256)
!30 = !DIGlobalVariableExpression(var: !31, expr: !DIExpression())
!31 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !32, isLocal: false, isDefinition: true)
!32 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !33)
!33 = !{!34, !39}
!34 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !35, size: 64)
!35 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !36, size: 64)
!36 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !37)
!37 = !{!38}
!38 = !DISubrange(count: 27, lowerBound: 0)
!39 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !40, size: 64, offset: 64)
!40 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !41, size: 64)
!41 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !42)
!42 = !{!43}
!43 = !DISubrange(count: 262144, lowerBound: 0)
!44 = !DIGlobalVariableExpression(var: !45, expr: !DIExpression())
!45 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !46, isLocal: false, isDefinition: true)
!46 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !47)
!47 = !{!48, !53, !54, !57}
!48 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !49, size: 64)
!49 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !50, size: 64)
!50 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !51)
!51 = !{!52}
!52 = !DISubrange(count: 2, lowerBound: 0)
!53 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !6, size: 64, offset: 64)
!54 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !55, size: 64, offset: 128)
!55 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !56, size: 64)
!56 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!57 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !17, size: 64, offset: 192)
!58 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, enums: !59, globals: !60)
!59 = !{}
!60 = !{!0, !30, !44}
!61 = !{i32 2, !"Debug Info Version", i32 3}
!62 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !63, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !58, retainedNodes: !66)
!63 = !DISubroutineType(types: !64)
!64 = !{!18, !65}
!65 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !24, size: 64)
!66 = !{!67}
!67 = !DILocalVariable(name: "ctx", arg: 1, scope: !62, file: !2, type: !65)
