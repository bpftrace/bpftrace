; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { i8*, i8*, i8*, i8* }
%"struct map_t.0" = type { i8*, i8*, i8*, i8* }
%"struct map_t.1" = type { i8*, i8*, i8*, i8* }
%"struct map_t.2" = type { i8*, i8*, i8*, i8* }
%"struct map_t.3" = type { i8*, i8*, i8*, i8* }
%"struct map_t.4" = type { i8*, i8* }
%"struct map_t.5" = type { i8*, i8*, i8*, i8* }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_a = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@AT_b = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !20
@AT_c = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !22
@AT_d = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !24
@AT_e = dso_local global %"struct map_t.3" zeroinitializer, section ".maps", !dbg !26
@ringbuf = dso_local global %"struct map_t.4" zeroinitializer, section ".maps", !dbg !36
@event_loss_counter = dso_local global %"struct map_t.5" zeroinitializer, section ".maps", !dbg !50

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(i8* %0) section "s_kprobe_f_1" !dbg !67 {
entry:
  %"@e_key" = alloca i64, align 8
  %"struct x.e" = alloca [4 x i8], align 1
  %"@d_val" = alloca i64, align 8
  %"@d_key" = alloca i64, align 8
  %"struct c.c" = alloca i8, align 1
  %"@c_val" = alloca i64, align 8
  %"@c_key" = alloca i64, align 8
  %"@b_val" = alloca i64, align 8
  %"@b_key" = alloca i64, align 8
  %"@a_val" = alloca i64, align 8
  %"@a_key" = alloca i64, align 8
  %"$x" = alloca i64, align 8
  %1 = bitcast i64* %"$x" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i64 0, i64* %"$x", align 8
  %2 = ptrtoint i8* %0 to i64
  store i64 %2, i64* %"$x", align 8
  %3 = load i64, i64* %"$x", align 8
  %4 = add i64 %3, 0
  %5 = inttoptr i64 %4 to i64*
  %6 = load volatile i64, i64* %5, align 8
  %7 = bitcast i64* %"@a_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %7)
  store i64 0, i64* %"@a_key", align 8
  %8 = bitcast i64* %"@a_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %8)
  store i64 %6, i64* %"@a_val", align 8
  %update_elem = call i64 inttoptr (i64 2 to i64 (%"struct map_t"*, i64*, i64*, i64)*)(%"struct map_t"* @AT_a, i64* %"@a_key", i64* %"@a_val", i64 0)
  %9 = bitcast i64* %"@a_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %9)
  %10 = bitcast i64* %"@a_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %10)
  %11 = load i64, i64* %"$x", align 8
  %12 = add i64 %11, 8
  %13 = add i64 %12, 0
  %14 = inttoptr i64 %13 to i16*
  %15 = load volatile i16, i16* %14, align 2
  %16 = bitcast i64* %"@b_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %16)
  store i64 0, i64* %"@b_key", align 8
  %17 = sext i16 %15 to i64
  %18 = bitcast i64* %"@b_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %18)
  store i64 %17, i64* %"@b_val", align 8
  %update_elem1 = call i64 inttoptr (i64 2 to i64 (%"struct map_t.0"*, i64*, i64*, i64)*)(%"struct map_t.0"* @AT_b, i64* %"@b_key", i64* %"@b_val", i64 0)
  %19 = bitcast i64* %"@b_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %19)
  %20 = bitcast i64* %"@b_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %20)
  %21 = load i64, i64* %"$x", align 8
  %22 = add i64 %21, 16
  %23 = add i64 %22, 0
  %24 = inttoptr i64 %23 to i8*
  %25 = load volatile i8, i8* %24, align 1
  %26 = bitcast i64* %"@c_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %26)
  store i64 0, i64* %"@c_key", align 8
  %27 = sext i8 %25 to i64
  %28 = bitcast i64* %"@c_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %28)
  store i64 %27, i64* %"@c_val", align 8
  %update_elem2 = call i64 inttoptr (i64 2 to i64 (%"struct map_t.1"*, i64*, i64*, i64)*)(%"struct map_t.1"* @AT_c, i64* %"@c_key", i64* %"@c_val", i64 0)
  %29 = bitcast i64* %"@c_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %29)
  %30 = bitcast i64* %"@c_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %30)
  %31 = load i64, i64* %"$x", align 8
  %32 = add i64 %31, 24
  %33 = inttoptr i64 %32 to i64*
  %34 = load volatile i64, i64* %33, align 8
  %35 = add i64 %34, 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %"struct c.c")
  %probe_read_kernel = call i64 inttoptr (i64 113 to i64 (i8*, i32, i64)*)(i8* %"struct c.c", i32 1, i64 %35)
  %36 = load i8, i8* %"struct c.c", align 1
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %"struct c.c")
  %37 = bitcast i64* %"@d_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %37)
  store i64 0, i64* %"@d_key", align 8
  %38 = sext i8 %36 to i64
  %39 = bitcast i64* %"@d_val" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %39)
  store i64 %38, i64* %"@d_val", align 8
  %update_elem3 = call i64 inttoptr (i64 2 to i64 (%"struct map_t.2"*, i64*, i64*, i64)*)(%"struct map_t.2"* @AT_d, i64* %"@d_key", i64* %"@d_val", i64 0)
  %40 = bitcast i64* %"@d_val" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %40)
  %41 = bitcast i64* %"@d_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %41)
  %42 = load i64, i64* %"$x", align 8
  %43 = add i64 %42, 32
  %44 = bitcast [4 x i8]* %"struct x.e" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %44)
  %probe_read_kernel4 = call i64 inttoptr (i64 113 to i64 ([4 x i8]*, i32, i64)*)([4 x i8]* %"struct x.e", i32 4, i64 %43)
  %45 = bitcast i64* %"@e_key" to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %45)
  store i64 0, i64* %"@e_key", align 8
  %update_elem5 = call i64 inttoptr (i64 2 to i64 (%"struct map_t.3"*, i64*, [4 x i8]*, i64)*)(%"struct map_t.3"* @AT_e, i64* %"@e_key", [4 x i8]* %"struct x.e", i64 0)
  %46 = bitcast i64* %"@e_key" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %46)
  %47 = bitcast [4 x i8]* %"struct x.e" to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %47)
  ret i64 0
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }

!llvm.dbg.cu = !{!63}
!llvm.module.flags = !{!66}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "AT_a", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
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
!21 = distinct !DIGlobalVariable(name: "AT_b", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!22 = !DIGlobalVariableExpression(var: !23, expr: !DIExpression())
!23 = distinct !DIGlobalVariable(name: "AT_c", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!24 = !DIGlobalVariableExpression(var: !25, expr: !DIExpression())
!25 = distinct !DIGlobalVariable(name: "AT_d", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!26 = !DIGlobalVariableExpression(var: !27, expr: !DIExpression())
!27 = distinct !DIGlobalVariable(name: "AT_e", linkageName: "global", scope: !2, file: !2, type: !28, isLocal: false, isDefinition: true)
!28 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !29)
!29 = !{!5, !11, !16, !30}
!30 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !31, size: 64, offset: 192)
!31 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !32, size: 64)
!32 = !DICompositeType(tag: DW_TAG_array_type, baseType: !33, size: 32, elements: !34)
!33 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!34 = !{!35}
!35 = !DISubrange(count: 4, lowerBound: 0)
!36 = !DIGlobalVariableExpression(var: !37, expr: !DIExpression())
!37 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !38, isLocal: false, isDefinition: true)
!38 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !39)
!39 = !{!40, !45}
!40 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !41, size: 64)
!41 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !42, size: 64)
!42 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !43)
!43 = !{!44}
!44 = !DISubrange(count: 27, lowerBound: 0)
!45 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !46, size: 64, offset: 64)
!46 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !47, size: 64)
!47 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !48)
!48 = !{!49}
!49 = !DISubrange(count: 262144, lowerBound: 0)
!50 = !DIGlobalVariableExpression(var: !51, expr: !DIExpression())
!51 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !52, isLocal: false, isDefinition: true)
!52 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !53)
!53 = !{!54, !59, !60, !19}
!54 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !55, size: 64)
!55 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !56, size: 64)
!56 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !57)
!57 = !{!58}
!58 = !DISubrange(count: 2, lowerBound: 0)
!59 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !6, size: 64, offset: 64)
!60 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !61, size: 64, offset: 128)
!61 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !62, size: 64)
!62 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!63 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, enums: !64, globals: !65)
!64 = !{}
!65 = !{!0, !20, !22, !24, !26, !36, !50}
!66 = !{i32 2, !"Debug Info Version", i32 3}
!67 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !68, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !63, retainedNodes: !71)
!68 = !DISubroutineType(types: !69)
!69 = !{!18, !70}
!70 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !33, size: 64)
!71 = !{!72}
!72 = !DILocalVariable(name: "ctx", arg: 1, scope: !67, file: !2, type: !70)
