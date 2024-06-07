; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { i8*, i8*, i8*, i8* }
%"struct map_t.0" = type { i8*, i8* }
%"struct map_t.1" = type { i8*, i8*, i8*, i8* }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_i = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@ringbuf = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !20
@event_loss_counter = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !34

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @BEGIN_1(i8* %0) section "s_BEGIN_1" !dbg !51 {
entry:
  %"@i_val47" = alloca i64, align 8
  %"@i_key46" = alloca i64, align 8
  %lookup_elem_val43 = alloca i64, align 8
  %"@i_key38" = alloca i64, align 8
  %"@i_val36" = alloca i64, align 8
  %"@i_key35" = alloca i64, align 8
  %lookup_elem_val32 = alloca i64, align 8
  %"@i_key27" = alloca i64, align 8
  %"@i_val25" = alloca i64, align 8
  %"@i_key24" = alloca i64, align 8
  %lookup_elem_val21 = alloca i64, align 8
  %"@i_key16" = alloca i64, align 8
  %"@i_val14" = alloca i64, align 8
  %"@i_key13" = alloca i64, align 8
  %lookup_elem_val10 = alloca i64, align 8
  %"@i_key5" = alloca i64, align 8
  %"@i_val3" = alloca i64, align 8
  %"@i_key2" = alloca i64, align 8
  %lookup_elem_val = alloca i64, align 8
  %"@i_key1" = alloca i64, align 8
  %"@i_val" = alloca i64, align 8
  %"@i_key" = alloca i64, align 8
  %1 = bitcast i64* %"@i_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 0, i64* %"@i_key", align 8
  %2 = bitcast i64* %"@i_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %2)
  store i64 0, i64* %"@i_val", align 8
  %update_elem = call i64 inttoptr (i64 2 to i64 (%"struct map_t"*, i64*, i64*, i64)*)(%"struct map_t"* @AT_i, i64* %"@i_key", i64* %"@i_val", i64 0)
  %3 = bitcast i64* %"@i_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %3)
  %4 = bitcast i64* %"@i_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %4)
  %5 = bitcast i64* %"@i_key1" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %5)
  store i64 0, i64* %"@i_key1", align 8
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (%"struct map_t"*, i64*)*)(%"struct map_t"* @AT_i, i64* %"@i_key1")
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
  %10 = bitcast i64* %"@i_key1" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %10)
  %11 = add i64 %8, 1
  %12 = bitcast i64* %"@i_key2" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %12)
  store i64 0, i64* %"@i_key2", align 8
  %13 = bitcast i64* %"@i_val3" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %13)
  store i64 %11, i64* %"@i_val3", align 8
  %update_elem4 = call i64 inttoptr (i64 2 to i64 (%"struct map_t"*, i64*, i64*, i64)*)(%"struct map_t"* @AT_i, i64* %"@i_key2", i64* %"@i_val3", i64 0)
  %14 = bitcast i64* %"@i_val3" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %14)
  %15 = bitcast i64* %"@i_key2" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %15)
  %16 = bitcast i64* %"@i_key5" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %16)
  store i64 0, i64* %"@i_key5", align 8
  %lookup_elem6 = call i8* inttoptr (i64 1 to i8* (%"struct map_t"*, i64*)*)(%"struct map_t"* @AT_i, i64* %"@i_key5")
  %17 = bitcast i64* %lookup_elem_val10 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %17)
  %map_lookup_cond11 = icmp ne i8* %lookup_elem6, null
  br i1 %map_lookup_cond11, label %lookup_success7, label %lookup_failure8

lookup_success7:                                  ; preds = %lookup_merge
  %cast12 = bitcast i8* %lookup_elem6 to i64*
  %18 = load i64, i64* %cast12, align 8
  store i64 %18, i64* %lookup_elem_val10, align 8
  br label %lookup_merge9

lookup_failure8:                                  ; preds = %lookup_merge
  store i64 0, i64* %lookup_elem_val10, align 8
  br label %lookup_merge9

lookup_merge9:                                    ; preds = %lookup_failure8, %lookup_success7
  %19 = load i64, i64* %lookup_elem_val10, align 8
  %20 = bitcast i64* %lookup_elem_val10 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %20)
  %21 = bitcast i64* %"@i_key5" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %21)
  %22 = add i64 %19, 1
  %23 = bitcast i64* %"@i_key13" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %23)
  store i64 0, i64* %"@i_key13", align 8
  %24 = bitcast i64* %"@i_val14" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %24)
  store i64 %22, i64* %"@i_val14", align 8
  %update_elem15 = call i64 inttoptr (i64 2 to i64 (%"struct map_t"*, i64*, i64*, i64)*)(%"struct map_t"* @AT_i, i64* %"@i_key13", i64* %"@i_val14", i64 0)
  %25 = bitcast i64* %"@i_val14" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %25)
  %26 = bitcast i64* %"@i_key13" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %26)
  %27 = bitcast i64* %"@i_key16" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %27)
  store i64 0, i64* %"@i_key16", align 8
  %lookup_elem17 = call i8* inttoptr (i64 1 to i8* (%"struct map_t"*, i64*)*)(%"struct map_t"* @AT_i, i64* %"@i_key16")
  %28 = bitcast i64* %lookup_elem_val21 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %28)
  %map_lookup_cond22 = icmp ne i8* %lookup_elem17, null
  br i1 %map_lookup_cond22, label %lookup_success18, label %lookup_failure19

lookup_success18:                                 ; preds = %lookup_merge9
  %cast23 = bitcast i8* %lookup_elem17 to i64*
  %29 = load i64, i64* %cast23, align 8
  store i64 %29, i64* %lookup_elem_val21, align 8
  br label %lookup_merge20

lookup_failure19:                                 ; preds = %lookup_merge9
  store i64 0, i64* %lookup_elem_val21, align 8
  br label %lookup_merge20

lookup_merge20:                                   ; preds = %lookup_failure19, %lookup_success18
  %30 = load i64, i64* %lookup_elem_val21, align 8
  %31 = bitcast i64* %lookup_elem_val21 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %31)
  %32 = bitcast i64* %"@i_key16" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %32)
  %33 = add i64 %30, 1
  %34 = bitcast i64* %"@i_key24" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %34)
  store i64 0, i64* %"@i_key24", align 8
  %35 = bitcast i64* %"@i_val25" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %35)
  store i64 %33, i64* %"@i_val25", align 8
  %update_elem26 = call i64 inttoptr (i64 2 to i64 (%"struct map_t"*, i64*, i64*, i64)*)(%"struct map_t"* @AT_i, i64* %"@i_key24", i64* %"@i_val25", i64 0)
  %36 = bitcast i64* %"@i_val25" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %36)
  %37 = bitcast i64* %"@i_key24" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %37)
  %38 = bitcast i64* %"@i_key27" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %38)
  store i64 0, i64* %"@i_key27", align 8
  %lookup_elem28 = call i8* inttoptr (i64 1 to i8* (%"struct map_t"*, i64*)*)(%"struct map_t"* @AT_i, i64* %"@i_key27")
  %39 = bitcast i64* %lookup_elem_val32 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %39)
  %map_lookup_cond33 = icmp ne i8* %lookup_elem28, null
  br i1 %map_lookup_cond33, label %lookup_success29, label %lookup_failure30

lookup_success29:                                 ; preds = %lookup_merge20
  %cast34 = bitcast i8* %lookup_elem28 to i64*
  %40 = load i64, i64* %cast34, align 8
  store i64 %40, i64* %lookup_elem_val32, align 8
  br label %lookup_merge31

lookup_failure30:                                 ; preds = %lookup_merge20
  store i64 0, i64* %lookup_elem_val32, align 8
  br label %lookup_merge31

lookup_merge31:                                   ; preds = %lookup_failure30, %lookup_success29
  %41 = load i64, i64* %lookup_elem_val32, align 8
  %42 = bitcast i64* %lookup_elem_val32 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %42)
  %43 = bitcast i64* %"@i_key27" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %43)
  %44 = add i64 %41, 1
  %45 = bitcast i64* %"@i_key35" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %45)
  store i64 0, i64* %"@i_key35", align 8
  %46 = bitcast i64* %"@i_val36" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %46)
  store i64 %44, i64* %"@i_val36", align 8
  %update_elem37 = call i64 inttoptr (i64 2 to i64 (%"struct map_t"*, i64*, i64*, i64)*)(%"struct map_t"* @AT_i, i64* %"@i_key35", i64* %"@i_val36", i64 0)
  %47 = bitcast i64* %"@i_val36" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %47)
  %48 = bitcast i64* %"@i_key35" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %48)
  %49 = bitcast i64* %"@i_key38" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %49)
  store i64 0, i64* %"@i_key38", align 8
  %lookup_elem39 = call i8* inttoptr (i64 1 to i8* (%"struct map_t"*, i64*)*)(%"struct map_t"* @AT_i, i64* %"@i_key38")
  %50 = bitcast i64* %lookup_elem_val43 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %50)
  %map_lookup_cond44 = icmp ne i8* %lookup_elem39, null
  br i1 %map_lookup_cond44, label %lookup_success40, label %lookup_failure41

lookup_success40:                                 ; preds = %lookup_merge31
  %cast45 = bitcast i8* %lookup_elem39 to i64*
  %51 = load i64, i64* %cast45, align 8
  store i64 %51, i64* %lookup_elem_val43, align 8
  br label %lookup_merge42

lookup_failure41:                                 ; preds = %lookup_merge31
  store i64 0, i64* %lookup_elem_val43, align 8
  br label %lookup_merge42

lookup_merge42:                                   ; preds = %lookup_failure41, %lookup_success40
  %52 = load i64, i64* %lookup_elem_val43, align 8
  %53 = bitcast i64* %lookup_elem_val43 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %53)
  %54 = bitcast i64* %"@i_key38" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %54)
  %55 = add i64 %52, 1
  %56 = bitcast i64* %"@i_key46" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %56)
  store i64 0, i64* %"@i_key46", align 8
  %57 = bitcast i64* %"@i_val47" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %57)
  store i64 %55, i64* %"@i_val47", align 8
  %update_elem48 = call i64 inttoptr (i64 2 to i64 (%"struct map_t"*, i64*, i64*, i64)*)(%"struct map_t"* @AT_i, i64* %"@i_key46", i64* %"@i_val47", i64 0)
  %58 = bitcast i64* %"@i_val47" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %58)
  %59 = bitcast i64* %"@i_key46" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %59)
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
!1 = distinct !DIGlobalVariable(name: "AT_i", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
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
