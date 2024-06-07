; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { i8*, i8*, i8*, i8* }
%"struct map_t.0" = type { i8*, i8* }
%"struct map_t.1" = type { i8*, i8*, i8*, i8* }
%"struct Foo_int32[4]__tuple_t" = type { [8 x i8], [4 x i32] }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_t = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@ringbuf = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !33
@event_loss_counter = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !47

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(i8* %0) section "s_kprobe_f_1" !dbg !64 {
entry:
  %"@t_key" = alloca i64, align 8
  %tuple = alloca %"struct Foo_int32[4]__tuple_t", align 8
  %1 = bitcast i8* %0 to i64*
  %2 = getelementptr i64, i64* %1, i64 14
  %arg0 = load volatile i64, i64* %2, align 8
  %3 = bitcast i8* %0 to i64*
  %4 = getelementptr i64, i64* %3, i64 13
  %arg1 = load volatile i64, i64* %4, align 8
  %5 = add i64 %arg1, 0
  %6 = bitcast %"struct Foo_int32[4]__tuple_t"* %tuple to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %6)
  %7 = bitcast %"struct Foo_int32[4]__tuple_t"* %tuple to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %7, i8 0, i64 24, i1 false)
  %8 = getelementptr %"struct Foo_int32[4]__tuple_t", %"struct Foo_int32[4]__tuple_t"* %tuple, i32 0, i32 0
  %probe_read_kernel = call i64 inttoptr (i64 113 to i64 ([8 x i8]*, i32, i64)*)([8 x i8]* %8, i32 8, i64 %arg0)
  %9 = getelementptr %"struct Foo_int32[4]__tuple_t", %"struct Foo_int32[4]__tuple_t"* %tuple, i32 0, i32 1
  %probe_read_kernel1 = call i64 inttoptr (i64 113 to i64 ([4 x i32]*, i32, i64)*)([4 x i32]* %9, i32 16, i64 %5)
  %10 = bitcast i64* %"@t_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %10)
  store i64 0, i64* %"@t_key", align 8
  %update_elem = call i64 inttoptr (i64 2 to i64 (%"struct map_t"*, i64*, %"struct Foo_int32[4]__tuple_t"*, i64)*)(%"struct map_t"* @AT_t, i64* %"@t_key", %"struct Foo_int32[4]__tuple_t"* %tuple, i64 0)
  %11 = bitcast i64* %"@t_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %11)
  %12 = bitcast %"struct Foo_int32[4]__tuple_t"* %tuple to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %12)
  ret i64 0
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn writeonly
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }
attributes #2 = { argmemonly nofree nosync nounwind willreturn writeonly }

!llvm.dbg.cu = !{!60}
!llvm.module.flags = !{!63}

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
!21 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 192, elements: !22)
!22 = !{!23, !28}
!23 = !DIDerivedType(tag: DW_TAG_member, scope: !2, file: !2, baseType: !24, size: 64)
!24 = !DICompositeType(tag: DW_TAG_array_type, baseType: !25, size: 64, elements: !26)
!25 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!26 = !{!27}
!27 = !DISubrange(count: 8, lowerBound: 0)
!28 = !DIDerivedType(tag: DW_TAG_member, scope: !2, file: !2, baseType: !29, size: 128, offset: 64)
!29 = !DICompositeType(tag: DW_TAG_array_type, baseType: !30, size: 128, elements: !31)
!30 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!31 = !{!32}
!32 = !DISubrange(count: 4, lowerBound: 0)
!33 = !DIGlobalVariableExpression(var: !34, expr: !DIExpression())
!34 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !35, isLocal: false, isDefinition: true)
!35 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !36)
!36 = !{!37, !42}
!37 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !38, size: 64)
!38 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !39, size: 64)
!39 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !40)
!40 = !{!41}
!41 = !DISubrange(count: 27, lowerBound: 0)
!42 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !43, size: 64, offset: 64)
!43 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !44, size: 64)
!44 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !45)
!45 = !{!46}
!46 = !DISubrange(count: 262144, lowerBound: 0)
!47 = !DIGlobalVariableExpression(var: !48, expr: !DIExpression())
!48 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !49, isLocal: false, isDefinition: true)
!49 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !50)
!50 = !{!51, !56, !57, !59}
!51 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !52, size: 64)
!52 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !53, size: 64)
!53 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !54)
!54 = !{!55}
!55 = !DISubrange(count: 2, lowerBound: 0)
!56 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !6, size: 64, offset: 64)
!57 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !58, size: 64, offset: 128)
!58 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !30, size: 64)
!59 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !17, size: 64, offset: 192)
!60 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, enums: !61, globals: !62)
!61 = !{}
!62 = !{!0, !33, !47}
!63 = !{i32 2, !"Debug Info Version", i32 3}
!64 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !65, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !60, retainedNodes: !68)
!65 = !DISubroutineType(types: !66)
!66 = !{!18, !67}
!67 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !25, size: 64)
!68 = !{!69}
!69 = !DILocalVariable(name: "ctx", arg: 1, scope: !64, file: !2, type: !67)
