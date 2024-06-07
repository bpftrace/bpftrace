; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { i8*, i8*, i8*, i8* }
%"struct map_t.0" = type { i8*, i8* }
%"struct map_t.1" = type { i8*, i8*, i8*, i8* }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_x = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@ringbuf = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !20
@event_loss_counter = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !34

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @BEGIN_1(i8* %0) section "s_BEGIN_1" !dbg !51 {
entry:
  %"@x_newval31" = alloca i64, align 8
  %lookup_elem_val28 = alloca i64, align 8
  %"@x_key23" = alloca i64, align 8
  %"@x_newval21" = alloca i64, align 8
  %lookup_elem_val18 = alloca i64, align 8
  %"@x_key13" = alloca i64, align 8
  %"@x_newval11" = alloca i64, align 8
  %lookup_elem_val8 = alloca i64, align 8
  %"@x_key3" = alloca i64, align 8
  %"@x_newval" = alloca i64, align 8
  %lookup_elem_val = alloca i64, align 8
  %"@x_key1" = alloca i64, align 8
  %"@x_val" = alloca i64, align 8
  %"@x_key" = alloca i64, align 8
  %1 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 0, i64* %"@x_key", align 8
  %2 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %2)
  store i64 10, i64* %"@x_val", align 8
  %update_elem = call i64 inttoptr (i64 2 to i64 (%"struct map_t"*, i64*, i64*, i64)*)(%"struct map_t"* @AT_x, i64* %"@x_key", i64* %"@x_val", i64 0)
  %3 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %3)
  %4 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %4)
  %5 = bitcast i64* %"@x_key1" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %5)
  store i64 0, i64* %"@x_key1", align 8
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (%"struct map_t"*, i64*)*)(%"struct map_t"* @AT_x, i64* %"@x_key1")
  %6 = bitcast i64* %lookup_elem_val to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %6)
  %map_lookup_cond = icmp ne i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  %cast = bitcast i8* %lookup_elem to i64*
  %7 = load i64, i64* %cast, align 8
  store i64 %7, i64* %lookup_elem_val, align 8
  br label %lookup_merge

lookup_failure:                                   ; preds = %entry
  store i64 0, i64* %lookup_elem_val, align 8
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  %8 = load i64, i64* %lookup_elem_val, align 8
  %9 = bitcast i64* %lookup_elem_val to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %9)
  %10 = bitcast i64* %"@x_newval" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %10)
  %11 = add i64 %8, 1
  store i64 %11, i64* %"@x_newval", align 8
  %update_elem2 = call i64 inttoptr (i64 2 to i64 (%"struct map_t"*, i64*, i64*, i64)*)(%"struct map_t"* @AT_x, i64* %"@x_key1", i64* %"@x_newval", i64 0)
  %12 = bitcast i64* %"@x_newval" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %12)
  %13 = bitcast i64* %"@x_key1" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %13)
  %14 = bitcast i64* %"@x_key3" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %14)
  store i64 0, i64* %"@x_key3", align 8
  %lookup_elem4 = call i8* inttoptr (i64 1 to i8* (%"struct map_t"*, i64*)*)(%"struct map_t"* @AT_x, i64* %"@x_key3")
  %15 = bitcast i64* %lookup_elem_val8 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %15)
  %map_lookup_cond9 = icmp ne i8* %lookup_elem4, null
  br i1 %map_lookup_cond9, label %lookup_success5, label %lookup_failure6

lookup_success5:                                  ; preds = %lookup_merge
  %cast10 = bitcast i8* %lookup_elem4 to i64*
  %16 = load i64, i64* %cast10, align 8
  store i64 %16, i64* %lookup_elem_val8, align 8
  br label %lookup_merge7

lookup_failure6:                                  ; preds = %lookup_merge
  store i64 0, i64* %lookup_elem_val8, align 8
  br label %lookup_merge7

lookup_merge7:                                    ; preds = %lookup_failure6, %lookup_success5
  %17 = load i64, i64* %lookup_elem_val8, align 8
  %18 = bitcast i64* %lookup_elem_val8 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %18)
  %19 = bitcast i64* %"@x_newval11" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %19)
  %20 = add i64 %17, 1
  store i64 %20, i64* %"@x_newval11", align 8
  %update_elem12 = call i64 inttoptr (i64 2 to i64 (%"struct map_t"*, i64*, i64*, i64)*)(%"struct map_t"* @AT_x, i64* %"@x_key3", i64* %"@x_newval11", i64 0)
  %21 = load i64, i64* %"@x_newval11", align 8
  %22 = bitcast i64* %"@x_newval11" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %22)
  %23 = bitcast i64* %"@x_key3" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %23)
  %24 = bitcast i64* %"@x_key13" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %24)
  store i64 0, i64* %"@x_key13", align 8
  %lookup_elem14 = call i8* inttoptr (i64 1 to i8* (%"struct map_t"*, i64*)*)(%"struct map_t"* @AT_x, i64* %"@x_key13")
  %25 = bitcast i64* %lookup_elem_val18 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %25)
  %map_lookup_cond19 = icmp ne i8* %lookup_elem14, null
  br i1 %map_lookup_cond19, label %lookup_success15, label %lookup_failure16

lookup_success15:                                 ; preds = %lookup_merge7
  %cast20 = bitcast i8* %lookup_elem14 to i64*
  %26 = load i64, i64* %cast20, align 8
  store i64 %26, i64* %lookup_elem_val18, align 8
  br label %lookup_merge17

lookup_failure16:                                 ; preds = %lookup_merge7
  store i64 0, i64* %lookup_elem_val18, align 8
  br label %lookup_merge17

lookup_merge17:                                   ; preds = %lookup_failure16, %lookup_success15
  %27 = load i64, i64* %lookup_elem_val18, align 8
  %28 = bitcast i64* %lookup_elem_val18 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %28)
  %29 = bitcast i64* %"@x_newval21" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %29)
  %30 = sub i64 %27, 1
  store i64 %30, i64* %"@x_newval21", align 8
  %update_elem22 = call i64 inttoptr (i64 2 to i64 (%"struct map_t"*, i64*, i64*, i64)*)(%"struct map_t"* @AT_x, i64* %"@x_key13", i64* %"@x_newval21", i64 0)
  %31 = bitcast i64* %"@x_newval21" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %31)
  %32 = bitcast i64* %"@x_key13" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %32)
  %33 = bitcast i64* %"@x_key23" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %33)
  store i64 0, i64* %"@x_key23", align 8
  %lookup_elem24 = call i8* inttoptr (i64 1 to i8* (%"struct map_t"*, i64*)*)(%"struct map_t"* @AT_x, i64* %"@x_key23")
  %34 = bitcast i64* %lookup_elem_val28 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %34)
  %map_lookup_cond29 = icmp ne i8* %lookup_elem24, null
  br i1 %map_lookup_cond29, label %lookup_success25, label %lookup_failure26

lookup_success25:                                 ; preds = %lookup_merge17
  %cast30 = bitcast i8* %lookup_elem24 to i64*
  %35 = load i64, i64* %cast30, align 8
  store i64 %35, i64* %lookup_elem_val28, align 8
  br label %lookup_merge27

lookup_failure26:                                 ; preds = %lookup_merge17
  store i64 0, i64* %lookup_elem_val28, align 8
  br label %lookup_merge27

lookup_merge27:                                   ; preds = %lookup_failure26, %lookup_success25
  %36 = load i64, i64* %lookup_elem_val28, align 8
  %37 = bitcast i64* %lookup_elem_val28 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %37)
  %38 = bitcast i64* %"@x_newval31" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %38)
  %39 = sub i64 %36, 1
  store i64 %39, i64* %"@x_newval31", align 8
  %update_elem32 = call i64 inttoptr (i64 2 to i64 (%"struct map_t"*, i64*, i64*, i64)*)(%"struct map_t"* @AT_x, i64* %"@x_key23", i64* %"@x_newval31", i64 0)
  %40 = load i64, i64* %"@x_newval31", align 8
  %41 = bitcast i64* %"@x_newval31" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %41)
  %42 = bitcast i64* %"@x_key23" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %42)
  ret i64 0
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }

!llvm.dbg.cu = !{!47}
!llvm.module.flags = !{!50}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "AT_x", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
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
