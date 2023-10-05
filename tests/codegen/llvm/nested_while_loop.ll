; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { i8*, i8*, i8*, i8* }

@AT_ = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @"interval:s:1"(i8* %0) section "s_interval:s:1_1" !dbg !24 {
entry:
  %"@_newval" = alloca i64, align 8
  %lookup_elem_val = alloca i64, align 8
  %"@_key" = alloca i64, align 8
  %"$j" = alloca i64, align 8
  %1 = bitcast i64* %"$j" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 0, i64* %"$j", align 8
  %"$i" = alloca i64, align 8
  %2 = bitcast i64* %"$i" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %2)
  store i64 0, i64* %"$i", align 8
  store i64 1, i64* %"$i", align 8
  br label %while_cond

while_cond:                                       ; preds = %while_end3, %entry
  %3 = load i64, i64* %"$i", align 8
  %4 = icmp sle i64 %3, 100
  %5 = zext i1 %4 to i64
  %true_cond = icmp ne i64 %5, 0
  br i1 %true_cond, label %while_body, label %while_end, !llvm.loop !32

while_body:                                       ; preds = %while_cond
  store i64 0, i64* %"$j", align 8
  %6 = load i64, i64* %"$i", align 8
  %7 = add i64 %6, 1
  store i64 %7, i64* %"$i", align 8
  br label %while_cond1

while_end:                                        ; preds = %while_cond
  ret i64 0

while_cond1:                                      ; preds = %lookup_merge, %while_body
  %8 = load i64, i64* %"$j", align 8
  %9 = icmp sle i64 %8, 100
  %10 = zext i1 %9 to i64
  %true_cond4 = icmp ne i64 %10, 0
  br i1 %true_cond4, label %while_body2, label %while_end3, !llvm.loop !32

while_body2:                                      ; preds = %while_cond1
  %11 = bitcast i64* %"@_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %11)
  store i64 0, i64* %"@_key", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (i64, i64*)*)(i64 %pseudo, i64* %"@_key")
  %12 = bitcast i64* %lookup_elem_val to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %12)
  %map_lookup_cond = icmp ne i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

while_end3:                                       ; preds = %while_cond1
  br label %while_cond

lookup_success:                                   ; preds = %while_body2
  %cast = bitcast i8* %lookup_elem to i64*
  %13 = load i64, i64* %cast, align 8
  store i64 %13, i64* %lookup_elem_val, align 8
  br label %lookup_merge

lookup_failure:                                   ; preds = %while_body2
  store i64 0, i64* %lookup_elem_val, align 8
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  %14 = load i64, i64* %lookup_elem_val, align 8
  %15 = bitcast i64* %lookup_elem_val to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %15)
  %16 = bitcast i64* %"@_newval" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %16)
  %17 = add i64 %14, 1
  store i64 %17, i64* %"@_newval", align 8
  %pseudo5 = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem = call i64 inttoptr (i64 2 to i64 (i64, i64*, i64*, i64)*)(i64 %pseudo5, i64* %"@_key", i64* %"@_newval", i64 0)
  %18 = bitcast i64* %"@_newval" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %18)
  %19 = bitcast i64* %"@_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %19)
  %20 = load i64, i64* %"$j", align 8
  %21 = add i64 %20, 1
  store i64 %21, i64* %"$j", align 8
  br label %while_cond1
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }

!llvm.dbg.cu = !{!20}
!llvm.module.flags = !{!23}

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
!20 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, enums: !21, globals: !22)
!21 = !{}
!22 = !{!0}
!23 = !{i32 2, !"Debug Info Version", i32 3}
!24 = distinct !DISubprogram(name: "interval_s_1", linkageName: "interval_s_1", scope: !2, file: !2, type: !25, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !20, retainedNodes: !29)
!25 = !DISubroutineType(types: !26)
!26 = !{!18, !27}
!27 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !28, size: 64)
!28 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!29 = !{!30, !31}
!30 = !DILocalVariable(name: "var0", scope: !24, file: !2, type: !18)
!31 = !DILocalVariable(name: "var1", arg: 1, scope: !24, file: !2, type: !27)
!32 = distinct !{!32, !33}
!33 = !{!"llvm.loop.unroll.disable"}
