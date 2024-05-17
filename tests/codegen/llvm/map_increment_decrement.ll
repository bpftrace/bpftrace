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
@ringbuf_loss_counter = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !34

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @BEGIN_1(i8* %0) section "s_BEGIN_1" !dbg !51 {
entry:
  %initial_value34 = alloca i64, align 8
  %lookup_elem_val31 = alloca i64, align 8
  %"@xpre_post_val26" = alloca i64, align 8
  %"@x_key25" = alloca i64, align 8
  %initial_value23 = alloca i64, align 8
  %lookup_elem_val20 = alloca i64, align 8
  %"@xpre_post_val15" = alloca i64, align 8
  %"@x_key14" = alloca i64, align 8
  %initial_value12 = alloca i64, align 8
  %lookup_elem_val9 = alloca i64, align 8
  %"@xpre_post_val4" = alloca i64, align 8
  %"@x_key3" = alloca i64, align 8
  %initial_value = alloca i64, align 8
  %lookup_elem_val = alloca i64, align 8
  %"@xpre_post_val" = alloca i64, align 8
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
  %6 = bitcast i64* %"@xpre_post_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %6)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (%"struct map_t"*, i64*)*)(%"struct map_t"* @AT_x, i64* %"@x_key1")
  %7 = bitcast i64* %lookup_elem_val to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %7)
  %map_lookup_cond = icmp ne i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  %cast = bitcast i8* %lookup_elem to i64*
  %8 = load i64, i64* %cast, align 8
  store i64 %8, i64* %"@xpre_post_val", align 8
  %9 = atomicrmw add i64* %cast, i64 1 seq_cst
  br label %lookup_merge

lookup_failure:                                   ; preds = %entry
  %10 = bitcast i64* %initial_value to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %10)
  store i64 1, i64* %initial_value, align 8
  %update_elem2 = call i64 inttoptr (i64 2 to i64 (%"struct map_t"*, i64*, i64*, i64)*)(%"struct map_t"* @AT_x, i64* %"@x_key1", i64* %initial_value, i64 1)
  %11 = bitcast i64* %initial_value to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %11)
  store i64 0, i64* %"@xpre_post_val", align 8
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  %12 = bitcast i64* %lookup_elem_val to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %12)
  %13 = load i64, i64* %"@xpre_post_val", align 8
  %14 = bitcast i64* %"@xpre_post_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %14)
  %15 = bitcast i64* %"@x_key1" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %15)
  %16 = bitcast i64* %"@x_key3" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %16)
  store i64 0, i64* %"@x_key3", align 8
  %17 = bitcast i64* %"@xpre_post_val4" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %17)
  %lookup_elem5 = call i8* inttoptr (i64 1 to i8* (%"struct map_t"*, i64*)*)(%"struct map_t"* @AT_x, i64* %"@x_key3")
  %18 = bitcast i64* %lookup_elem_val9 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %18)
  %map_lookup_cond10 = icmp ne i8* %lookup_elem5, null
  br i1 %map_lookup_cond10, label %lookup_success6, label %lookup_failure7

lookup_success6:                                  ; preds = %lookup_merge
  %cast11 = bitcast i8* %lookup_elem5 to i64*
  %19 = atomicrmw add i64* %cast11, i64 1 seq_cst
  %20 = load i64, i64* %cast11, align 8
  store i64 %20, i64* %"@xpre_post_val4", align 8
  br label %lookup_merge8

lookup_failure7:                                  ; preds = %lookup_merge
  %21 = bitcast i64* %initial_value12 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %21)
  store i64 1, i64* %initial_value12, align 8
  %update_elem13 = call i64 inttoptr (i64 2 to i64 (%"struct map_t"*, i64*, i64*, i64)*)(%"struct map_t"* @AT_x, i64* %"@x_key3", i64* %initial_value12, i64 1)
  %22 = bitcast i64* %initial_value12 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %22)
  store i64 1, i64* %"@xpre_post_val4", align 8
  br label %lookup_merge8

lookup_merge8:                                    ; preds = %lookup_failure7, %lookup_success6
  %23 = bitcast i64* %lookup_elem_val9 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %23)
  %24 = load i64, i64* %"@xpre_post_val4", align 8
  %25 = bitcast i64* %"@xpre_post_val4" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %25)
  %26 = bitcast i64* %"@x_key3" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %26)
  %27 = bitcast i64* %"@x_key14" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %27)
  store i64 0, i64* %"@x_key14", align 8
  %28 = bitcast i64* %"@xpre_post_val15" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %28)
  %lookup_elem16 = call i8* inttoptr (i64 1 to i8* (%"struct map_t"*, i64*)*)(%"struct map_t"* @AT_x, i64* %"@x_key14")
  %29 = bitcast i64* %lookup_elem_val20 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %29)
  %map_lookup_cond21 = icmp ne i8* %lookup_elem16, null
  br i1 %map_lookup_cond21, label %lookup_success17, label %lookup_failure18

lookup_success17:                                 ; preds = %lookup_merge8
  %cast22 = bitcast i8* %lookup_elem16 to i64*
  %30 = load i64, i64* %cast22, align 8
  store i64 %30, i64* %"@xpre_post_val15", align 8
  %31 = atomicrmw add i64* %cast22, i64 -1 seq_cst
  br label %lookup_merge19

lookup_failure18:                                 ; preds = %lookup_merge8
  %32 = bitcast i64* %initial_value23 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %32)
  store i64 -1, i64* %initial_value23, align 8
  %update_elem24 = call i64 inttoptr (i64 2 to i64 (%"struct map_t"*, i64*, i64*, i64)*)(%"struct map_t"* @AT_x, i64* %"@x_key14", i64* %initial_value23, i64 1)
  %33 = bitcast i64* %initial_value23 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %33)
  store i64 0, i64* %"@xpre_post_val15", align 8
  br label %lookup_merge19

lookup_merge19:                                   ; preds = %lookup_failure18, %lookup_success17
  %34 = bitcast i64* %lookup_elem_val20 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %34)
  %35 = load i64, i64* %"@xpre_post_val15", align 8
  %36 = bitcast i64* %"@xpre_post_val15" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %36)
  %37 = bitcast i64* %"@x_key14" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %37)
  %38 = bitcast i64* %"@x_key25" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %38)
  store i64 0, i64* %"@x_key25", align 8
  %39 = bitcast i64* %"@xpre_post_val26" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %39)
  %lookup_elem27 = call i8* inttoptr (i64 1 to i8* (%"struct map_t"*, i64*)*)(%"struct map_t"* @AT_x, i64* %"@x_key25")
  %40 = bitcast i64* %lookup_elem_val31 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %40)
  %map_lookup_cond32 = icmp ne i8* %lookup_elem27, null
  br i1 %map_lookup_cond32, label %lookup_success28, label %lookup_failure29

lookup_success28:                                 ; preds = %lookup_merge19
  %cast33 = bitcast i8* %lookup_elem27 to i64*
  %41 = atomicrmw add i64* %cast33, i64 -1 seq_cst
  %42 = load i64, i64* %cast33, align 8
  store i64 %42, i64* %"@xpre_post_val26", align 8
  br label %lookup_merge30

lookup_failure29:                                 ; preds = %lookup_merge19
  %43 = bitcast i64* %initial_value34 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %43)
  store i64 -1, i64* %initial_value34, align 8
  %update_elem35 = call i64 inttoptr (i64 2 to i64 (%"struct map_t"*, i64*, i64*, i64)*)(%"struct map_t"* @AT_x, i64* %"@x_key25", i64* %initial_value34, i64 1)
  %44 = bitcast i64* %initial_value34 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %44)
  store i64 -1, i64* %"@xpre_post_val26", align 8
  br label %lookup_merge30

lookup_merge30:                                   ; preds = %lookup_failure29, %lookup_success28
  %45 = bitcast i64* %lookup_elem_val31 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %45)
  %46 = load i64, i64* %"@xpre_post_val26", align 8
  %47 = bitcast i64* %"@xpre_post_val26" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %47)
  %48 = bitcast i64* %"@x_key25" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %48)
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
!35 = distinct !DIGlobalVariable(name: "ringbuf_loss_counter", linkageName: "global", scope: !2, file: !2, type: !36, isLocal: false, isDefinition: true)
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
