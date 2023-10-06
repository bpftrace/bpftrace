; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { i8*, i8*, i8*, i8* }
%"struct map_t.0" = type { i8*, i8* }
%"struct map_t.1" = type { i8*, i8*, i8*, i8* }

@AT_x = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@ringbuf = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !20
@ringbuf_loss_counter = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !34

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @BEGIN(i8* %0) section "s_BEGIN_1" !dbg !51 {
entry:
  %"@x_newval38" = alloca i64, align 8
  %lookup_elem_val35 = alloca i64, align 8
  %"@x_key29" = alloca i64, align 8
  %"@x_newval26" = alloca i64, align 8
  %lookup_elem_val23 = alloca i64, align 8
  %"@x_key17" = alloca i64, align 8
  %"@x_newval14" = alloca i64, align 8
  %lookup_elem_val11 = alloca i64, align 8
  %"@x_key5" = alloca i64, align 8
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
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo, i64* %"@x_key", i64* %"@x_val", i64 0)
  %3 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %3)
  %4 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %4)
  %5 = bitcast i64* %"@x_key1" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %5)
  store i64 0, i64* %"@x_key1", align 8
  %pseudo2 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo2, i64* %"@x_key1")
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
  %pseudo3 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem4 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo3, i64* %"@x_key1", i64* %"@x_newval", i64 0)
  %12 = bitcast i64* %"@x_newval" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %12)
  %13 = bitcast i64* %"@x_key1" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %13)
  %14 = bitcast i64* %"@x_key5" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %14)
  store i64 0, i64* %"@x_key5", align 8
  %pseudo6 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %lookup_elem7 = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo6, i64* %"@x_key5")
  %15 = bitcast i64* %lookup_elem_val11 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %15)
  %map_lookup_cond12 = icmp ne i8* %lookup_elem7, null
  br i1 %map_lookup_cond12, label %lookup_success8, label %lookup_failure9

lookup_success8:                                  ; preds = %lookup_merge
  %cast13 = bitcast i8* %lookup_elem7 to i64*
  %16 = load i64, i64* %cast13, align 8
  store i64 %16, i64* %lookup_elem_val11, align 8
  br label %lookup_merge10

lookup_failure9:                                  ; preds = %lookup_merge
  store i64 0, i64* %lookup_elem_val11, align 8
  br label %lookup_merge10

lookup_merge10:                                   ; preds = %lookup_failure9, %lookup_success8
  %17 = load i64, i64* %lookup_elem_val11, align 8
  %18 = bitcast i64* %lookup_elem_val11 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %18)
  %19 = bitcast i64* %"@x_newval14" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %19)
  %20 = add i64 %17, 1
  store i64 %20, i64* %"@x_newval14", align 8
  %pseudo15 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem16 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo15, i64* %"@x_key5", i64* %"@x_newval14", i64 0)
  %21 = load i64, i64* %"@x_newval14", align 8
  %22 = bitcast i64* %"@x_newval14" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %22)
  %23 = bitcast i64* %"@x_key5" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %23)
  %24 = bitcast i64* %"@x_key17" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %24)
  store i64 0, i64* %"@x_key17", align 8
  %pseudo18 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %lookup_elem19 = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo18, i64* %"@x_key17")
  %25 = bitcast i64* %lookup_elem_val23 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %25)
  %map_lookup_cond24 = icmp ne i8* %lookup_elem19, null
  br i1 %map_lookup_cond24, label %lookup_success20, label %lookup_failure21

lookup_success20:                                 ; preds = %lookup_merge10
  %cast25 = bitcast i8* %lookup_elem19 to i64*
  %26 = load i64, i64* %cast25, align 8
  store i64 %26, i64* %lookup_elem_val23, align 8
  br label %lookup_merge22

lookup_failure21:                                 ; preds = %lookup_merge10
  store i64 0, i64* %lookup_elem_val23, align 8
  br label %lookup_merge22

lookup_merge22:                                   ; preds = %lookup_failure21, %lookup_success20
  %27 = load i64, i64* %lookup_elem_val23, align 8
  %28 = bitcast i64* %lookup_elem_val23 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %28)
  %29 = bitcast i64* %"@x_newval26" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %29)
  %30 = sub i64 %27, 1
  store i64 %30, i64* %"@x_newval26", align 8
  %pseudo27 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem28 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo27, i64* %"@x_key17", i64* %"@x_newval26", i64 0)
  %31 = bitcast i64* %"@x_newval26" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %31)
  %32 = bitcast i64* %"@x_key17" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %32)
  %33 = bitcast i64* %"@x_key29" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %33)
  store i64 0, i64* %"@x_key29", align 8
  %pseudo30 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %lookup_elem31 = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo30, i64* %"@x_key29")
  %34 = bitcast i64* %lookup_elem_val35 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %34)
  %map_lookup_cond36 = icmp ne i8* %lookup_elem31, null
  br i1 %map_lookup_cond36, label %lookup_success32, label %lookup_failure33

lookup_success32:                                 ; preds = %lookup_merge22
  %cast37 = bitcast i8* %lookup_elem31 to i64*
  %35 = load i64, i64* %cast37, align 8
  store i64 %35, i64* %lookup_elem_val35, align 8
  br label %lookup_merge34

lookup_failure33:                                 ; preds = %lookup_merge22
  store i64 0, i64* %lookup_elem_val35, align 8
  br label %lookup_merge34

lookup_merge34:                                   ; preds = %lookup_failure33, %lookup_success32
  %36 = load i64, i64* %lookup_elem_val35, align 8
  %37 = bitcast i64* %lookup_elem_val35 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %37)
  %38 = bitcast i64* %"@x_newval38" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %38)
  %39 = sub i64 %36, 1
  store i64 %39, i64* %"@x_newval38", align 8
  %pseudo39 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem40 = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo39, i64* %"@x_key29", i64* %"@x_newval38", i64 0)
  %40 = load i64, i64* %"@x_newval38", align 8
  %41 = bitcast i64* %"@x_newval38" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %41)
  %42 = bitcast i64* %"@x_key29" to i8*
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
!51 = distinct !DISubprogram(name: "BEGIN", linkageName: "BEGIN", scope: !2, file: !2, type: !52, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !47, retainedNodes: !56)
!52 = !DISubroutineType(types: !53)
!53 = !{!18, !54}
!54 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !55, size: 64)
!55 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!56 = !{!57, !58}
!57 = !DILocalVariable(name: "var0", scope: !51, file: !2, type: !18)
!58 = !DILocalVariable(name: "var1", arg: 1, scope: !51, file: !2, type: !54)
