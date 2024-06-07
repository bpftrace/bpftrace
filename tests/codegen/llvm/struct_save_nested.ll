; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { i8*, i8*, i8*, i8* }
%"struct map_t.0" = type { i8*, i8*, i8*, i8* }
%"struct map_t.1" = type { i8*, i8*, i8*, i8* }
%"struct map_t.2" = type { i8*, i8* }
%"struct map_t.3" = type { i8*, i8*, i8*, i8* }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_bar = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@AT_foo = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !25
@AT_x = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !34
@ringbuf = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !39
@event_loss_counter = dso_local global %"struct map_t.3" zeroinitializer, section ".maps", !dbg !53

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(i8* %0) section "s_kprobe_f_1" !dbg !70 {
entry:
  %"@x_val" = alloca i64, align 8
  %"@x_key" = alloca i64, align 8
  %lookup_elem_val8 = alloca [16 x i8], align 1
  %"@foo_key3" = alloca i64, align 8
  %"@bar_key" = alloca i64, align 8
  %lookup_elem_val = alloca [16 x i8], align 1
  %"@foo_key1" = alloca i64, align 8
  %"@foo_val" = alloca [16 x i8], align 1
  %"@foo_key" = alloca i64, align 8
  %1 = bitcast i8* %0 to i64*
  %2 = getelementptr i64, i64* %1, i64 14
  %arg0 = load volatile i64, i64* %2, align 8
  %3 = bitcast i64* %"@foo_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %3)
  store i64 0, i64* %"@foo_key", align 8
  %4 = bitcast [16 x i8]* %"@foo_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %4)
  %probe_read_kernel = call i64 inttoptr (i64 113 to i64 ([16 x i8]*, i32, i64)*)([16 x i8]* %"@foo_val", i32 16, i64 %arg0)
  %update_elem = call i64 inttoptr (i64 2 to i64 (%"struct map_t.0"*, i64*, [16 x i8]*, i64)*)(%"struct map_t.0"* @AT_foo, i64* %"@foo_key", [16 x i8]* %"@foo_val", i64 0)
  %5 = bitcast [16 x i8]* %"@foo_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %5)
  %6 = bitcast i64* %"@foo_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %6)
  %7 = bitcast i64* %"@foo_key1" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %7)
  store i64 0, i64* %"@foo_key1", align 8
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (%"struct map_t.0"*, i64*)*)(%"struct map_t.0"* @AT_foo, i64* %"@foo_key1")
  %8 = bitcast [16 x i8]* %lookup_elem_val to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %8)
  %map_lookup_cond = icmp ne i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  %9 = bitcast [16 x i8]* %lookup_elem_val to i8*
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* align 1 %9, i8* align 1 %lookup_elem, i64 16, i1 false)
  br label %lookup_merge

lookup_failure:                                   ; preds = %entry
  %10 = bitcast [16 x i8]* %lookup_elem_val to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %10, i8 0, i64 16, i1 false)
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  %11 = bitcast i64* %"@foo_key1" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %11)
  %12 = getelementptr [16 x i8], [16 x i8]* %lookup_elem_val, i32 0, i64 4
  %13 = bitcast i8* %12 to [8 x i8]*
  %14 = bitcast i64* %"@bar_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %14)
  store i64 0, i64* %"@bar_key", align 8
  %update_elem2 = call i64 inttoptr (i64 2 to i64 (%"struct map_t"*, i64*, [8 x i8]*, i64)*)(%"struct map_t"* @AT_bar, i64* %"@bar_key", [8 x i8]* %13, i64 0)
  %15 = bitcast i64* %"@bar_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %15)
  %16 = bitcast [16 x i8]* %lookup_elem_val to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %16)
  %17 = bitcast i64* %"@foo_key3" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %17)
  store i64 0, i64* %"@foo_key3", align 8
  %lookup_elem4 = call i8* inttoptr (i64 1 to i8* (%"struct map_t.0"*, i64*)*)(%"struct map_t.0"* @AT_foo, i64* %"@foo_key3")
  %18 = bitcast [16 x i8]* %lookup_elem_val8 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %18)
  %map_lookup_cond9 = icmp ne i8* %lookup_elem4, null
  br i1 %map_lookup_cond9, label %lookup_success5, label %lookup_failure6

lookup_success5:                                  ; preds = %lookup_merge
  %19 = bitcast [16 x i8]* %lookup_elem_val8 to i8*
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* align 1 %19, i8* align 1 %lookup_elem4, i64 16, i1 false)
  br label %lookup_merge7

lookup_failure6:                                  ; preds = %lookup_merge
  %20 = bitcast [16 x i8]* %lookup_elem_val8 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %20, i8 0, i64 16, i1 false)
  br label %lookup_merge7

lookup_merge7:                                    ; preds = %lookup_failure6, %lookup_success5
  %21 = bitcast i64* %"@foo_key3" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %21)
  %22 = getelementptr [16 x i8], [16 x i8]* %lookup_elem_val8, i32 0, i64 4
  %23 = bitcast i8* %22 to [8 x i8]*
  %24 = getelementptr [8 x i8], [8 x i8]* %23, i32 0, i64 0
  %25 = bitcast i8* %24 to i32*
  %26 = load volatile i32, i32* %25, align 4
  %27 = bitcast [16 x i8]* %lookup_elem_val8 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %27)
  %28 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %28)
  store i64 0, i64* %"@x_key", align 8
  %29 = sext i32 %26 to i64
  %30 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %30)
  store i64 %29, i64* %"@x_val", align 8
  %update_elem10 = call i64 inttoptr (i64 2 to i64 (%"struct map_t.1"*, i64*, i64*, i64)*)(%"struct map_t.1"* @AT_x, i64* %"@x_key", i64* %"@x_val", i64 0)
  %31 = bitcast i64* %"@x_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %31)
  %32 = bitcast i64* %"@x_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %32)
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

!llvm.dbg.cu = !{!66}
!llvm.module.flags = !{!69}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "AT_bar", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
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
!21 = !DICompositeType(tag: DW_TAG_array_type, baseType: !22, size: 64, elements: !23)
!22 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!23 = !{!24}
!24 = !DISubrange(count: 8, lowerBound: 0)
!25 = !DIGlobalVariableExpression(var: !26, expr: !DIExpression())
!26 = distinct !DIGlobalVariable(name: "AT_foo", linkageName: "global", scope: !2, file: !2, type: !27, isLocal: false, isDefinition: true)
!27 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !28)
!28 = !{!5, !11, !16, !29}
!29 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !30, size: 64, offset: 192)
!30 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !31, size: 64)
!31 = !DICompositeType(tag: DW_TAG_array_type, baseType: !22, size: 128, elements: !32)
!32 = !{!33}
!33 = !DISubrange(count: 16, lowerBound: 0)
!34 = !DIGlobalVariableExpression(var: !35, expr: !DIExpression())
!35 = distinct !DIGlobalVariable(name: "AT_x", linkageName: "global", scope: !2, file: !2, type: !36, isLocal: false, isDefinition: true)
!36 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !37)
!37 = !{!5, !11, !16, !38}
!38 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !17, size: 64, offset: 192)
!39 = !DIGlobalVariableExpression(var: !40, expr: !DIExpression())
!40 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !41, isLocal: false, isDefinition: true)
!41 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !42)
!42 = !{!43, !48}
!43 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !44, size: 64)
!44 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !45, size: 64)
!45 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !46)
!46 = !{!47}
!47 = !DISubrange(count: 27, lowerBound: 0)
!48 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !49, size: 64, offset: 64)
!49 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !50, size: 64)
!50 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !51)
!51 = !{!52}
!52 = !DISubrange(count: 262144, lowerBound: 0)
!53 = !DIGlobalVariableExpression(var: !54, expr: !DIExpression())
!54 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !55, isLocal: false, isDefinition: true)
!55 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !56)
!56 = !{!57, !62, !63, !38}
!57 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !58, size: 64)
!58 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !59, size: 64)
!59 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !60)
!60 = !{!61}
!61 = !DISubrange(count: 2, lowerBound: 0)
!62 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !6, size: 64, offset: 64)
!63 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !64, size: 64, offset: 128)
!64 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !65, size: 64)
!65 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!66 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, enums: !67, globals: !68)
!67 = !{}
!68 = !{!0, !25, !34, !39, !53}
!69 = !{i32 2, !"Debug Info Version", i32 3}
!70 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !71, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !66, retainedNodes: !74)
!71 = !DISubroutineType(types: !72)
!72 = !{!18, !73}
!73 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !22, size: 64)
!74 = !{!75}
!75 = !DILocalVariable(name: "ctx", arg: 1, scope: !70, file: !2, type: !73)
