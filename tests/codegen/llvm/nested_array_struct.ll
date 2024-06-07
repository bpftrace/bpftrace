; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { i8*, i8*, i8*, i8* }
%"struct map_t.0" = type { i8*, i8*, i8*, i8* }
%"struct map_t.1" = type { i8*, i8* }
%"struct map_t.2" = type { i8*, i8*, i8*, i8* }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_ = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@AT_bar = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !20
@ringbuf = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !34
@event_loss_counter = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !48

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(i8* %0) section "s_kprobe_f_1" !dbg !63 {
entry:
  %"@_val" = alloca i64, align 8
  %"@_key" = alloca i64, align 8
  %lookup_elem_val = alloca [2 x [2 x [4 x i8]]], align 1
  %"@bar_key1" = alloca i64, align 8
  %"@bar_val" = alloca [2 x [2 x [4 x i8]]], align 1
  %"@bar_key" = alloca i64, align 8
  %1 = bitcast i8* %0 to i64*
  %2 = getelementptr i64, i64* %1, i64 14
  %arg0 = load volatile i64, i64* %2, align 8
  %3 = add i64 %arg0, 0
  %4 = bitcast i64* %"@bar_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %4)
  store i64 42, i64* %"@bar_key", align 8
  %5 = bitcast [2 x [2 x [4 x i8]]]* %"@bar_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %5)
  %probe_read_kernel = call i64 inttoptr (i64 113 to i64 ([2 x [2 x [4 x i8]]]*, i32, i64)*)([2 x [2 x [4 x i8]]]* %"@bar_val", i32 16, i64 %3)
  %update_elem = call i64 inttoptr (i64 2 to i64 (%"struct map_t.0"*, i64*, [2 x [2 x [4 x i8]]]*, i64)*)(%"struct map_t.0"* @AT_bar, i64* %"@bar_key", [2 x [2 x [4 x i8]]]* %"@bar_val", i64 0)
  %6 = bitcast [2 x [2 x [4 x i8]]]* %"@bar_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %6)
  %7 = bitcast i64* %"@bar_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %7)
  %8 = bitcast i64* %"@bar_key1" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %8)
  store i64 42, i64* %"@bar_key1", align 8
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (%"struct map_t.0"*, i64*)*)(%"struct map_t.0"* @AT_bar, i64* %"@bar_key1")
  %9 = bitcast [2 x [2 x [4 x i8]]]* %lookup_elem_val to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %9)
  %map_lookup_cond = icmp ne i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  %10 = bitcast [2 x [2 x [4 x i8]]]* %lookup_elem_val to i8*
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* align 1 %10, i8* align 1 %lookup_elem, i64 16, i1 false)
  br label %lookup_merge

lookup_failure:                                   ; preds = %entry
  %11 = bitcast [2 x [2 x [4 x i8]]]* %lookup_elem_val to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %11, i8 0, i64 16, i1 false)
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  %12 = bitcast i64* %"@bar_key1" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %12)
  %13 = getelementptr [2 x [2 x [4 x i8]]], [2 x [2 x [4 x i8]]]* %lookup_elem_val, i32 0, i64 0
  %14 = getelementptr [2 x [4 x i8]], [2 x [4 x i8]]* %13, i32 0, i64 1
  %15 = getelementptr [4 x i8], [4 x i8]* %14, i32 0, i64 0
  %16 = bitcast i8* %15 to i32*
  %17 = load volatile i32, i32* %16, align 4
  %18 = bitcast [2 x [2 x [4 x i8]]]* %lookup_elem_val to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %18)
  %19 = bitcast i64* %"@_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %19)
  store i64 0, i64* %"@_key", align 8
  %20 = sext i32 %17 to i64
  %21 = bitcast i64* %"@_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %21)
  store i64 %20, i64* %"@_val", align 8
  %update_elem2 = call i64 inttoptr (i64 2 to i64 (%"struct map_t"*, i64*, i64*, i64)*)(%"struct map_t"* @AT_, i64* %"@_key", i64* %"@_val", i64 0)
  %22 = bitcast i64* %"@_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %22)
  %23 = bitcast i64* %"@_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %23)
  ret i64 0
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.memcpy.p0i8.p0i8.i64(i8* noalias nocapture writeonly %0, i8* noalias nocapture readonly %1, i64 %2, i1 immarg %3) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn writeonly
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }
attributes #2 = { argmemonly nofree nosync nounwind willreturn writeonly }

!llvm.dbg.cu = !{!59}
!llvm.module.flags = !{!62}

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
!21 = distinct !DIGlobalVariable(name: "AT_bar", linkageName: "global", scope: !2, file: !2, type: !22, isLocal: false, isDefinition: true)
!22 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !23)
!23 = !{!5, !11, !16, !24}
!24 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !25, size: 64, offset: 192)
!25 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !26, size: 64)
!26 = !DICompositeType(tag: DW_TAG_array_type, baseType: !27, size: 128, elements: !32)
!27 = !DICompositeType(tag: DW_TAG_array_type, baseType: !28, size: 64, elements: !32)
!28 = !DICompositeType(tag: DW_TAG_array_type, baseType: !29, size: 32, elements: !30)
!29 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!30 = !{!31}
!31 = !DISubrange(count: 4, lowerBound: 0)
!32 = !{!33}
!33 = !DISubrange(count: 2, lowerBound: 0)
!34 = !DIGlobalVariableExpression(var: !35, expr: !DIExpression())
!35 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !36, isLocal: false, isDefinition: true)
!36 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !37)
!37 = !{!38, !43}
!38 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !39, size: 64)
!39 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !40, size: 64)
!40 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !41)
!41 = !{!42}
!42 = !DISubrange(count: 27, lowerBound: 0)
!43 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !44, size: 64, offset: 64)
!44 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !45, size: 64)
!45 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !46)
!46 = !{!47}
!47 = !DISubrange(count: 262144, lowerBound: 0)
!48 = !DIGlobalVariableExpression(var: !49, expr: !DIExpression())
!49 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !50, isLocal: false, isDefinition: true)
!50 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !51)
!51 = !{!52, !55, !56, !19}
!52 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !53, size: 64)
!53 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !54, size: 64)
!54 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !32)
!55 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !6, size: 64, offset: 64)
!56 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !57, size: 64, offset: 128)
!57 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !58, size: 64)
!58 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!59 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, enums: !60, globals: !61)
!60 = !{}
!61 = !{!0, !20, !34, !48}
!62 = !{i32 2, !"Debug Info Version", i32 3}
!63 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !64, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !59, retainedNodes: !67)
!64 = !DISubroutineType(types: !65)
!65 = !{!18, !66}
!66 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !29, size: 64)
!67 = !{!68}
!68 = !DILocalVariable(name: "ctx", arg: 1, scope: !63, file: !2, type: !66)
