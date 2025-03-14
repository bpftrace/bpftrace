; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr, ptr, ptr }
%"struct map_t.1" = type { ptr, ptr, ptr, ptr }
%"struct map_t.2" = type { ptr, ptr, ptr, ptr }
%"struct map_t.3" = type { ptr, ptr, ptr, ptr }
%"struct map_t.4" = type { ptr, ptr }
%"struct map_t.5" = type { ptr, ptr, ptr, ptr }

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@AT_a = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !7
@AT_b = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !22
@AT_c = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !24
@AT_d = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !26
@AT_e = dso_local global %"struct map_t.3" zeroinitializer, section ".maps", !dbg !28
@ringbuf = dso_local global %"struct map_t.4" zeroinitializer, section ".maps", !dbg !34
@event_loss_counter = dso_local global %"struct map_t.5" zeroinitializer, section ".maps", !dbg !48

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(ptr %0) section "s_kprobe_f_1" !dbg !63 {
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
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$x")
  store i64 0, ptr %"$x", align 8
  store ptr %0, ptr %"$x", align 8
  %1 = load i64, ptr %"$x", align 8
  %2 = inttoptr i64 %1 to ptr
  %3 = call ptr @llvm.preserve.static.offset(ptr %2)
  %4 = getelementptr i8, ptr %3, i64 0
  %5 = load volatile i64, ptr %4, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@a_key")
  store i64 0, ptr %"@a_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@a_val")
  store i64 %5, ptr %"@a_val", align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_a, ptr %"@a_key", ptr %"@a_val", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@a_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@a_key")
  %6 = load i64, ptr %"$x", align 8
  %7 = inttoptr i64 %6 to ptr
  %8 = call ptr @llvm.preserve.static.offset(ptr %7)
  %9 = getelementptr i8, ptr %8, i64 8
  %10 = ptrtoint ptr %9 to i64
  %11 = inttoptr i64 %10 to ptr
  %12 = call ptr @llvm.preserve.static.offset(ptr %11)
  %13 = getelementptr i8, ptr %12, i64 0
  %14 = load volatile i16, ptr %13, align 2
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@b_key")
  store i64 0, ptr %"@b_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@b_val")
  %15 = sext i16 %14 to i64
  store i64 %15, ptr %"@b_val", align 8
  %update_elem1 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_b, ptr %"@b_key", ptr %"@b_val", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@b_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@b_key")
  %16 = load i64, ptr %"$x", align 8
  %17 = inttoptr i64 %16 to ptr
  %18 = call ptr @llvm.preserve.static.offset(ptr %17)
  %19 = getelementptr i8, ptr %18, i64 16
  %20 = call ptr @llvm.preserve.static.offset(ptr %19)
  %21 = getelementptr i8, ptr %20, i64 0
  %22 = load volatile i8, ptr %21, align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@c_key")
  store i64 0, ptr %"@c_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@c_val")
  %23 = sext i8 %22 to i64
  store i64 %23, ptr %"@c_val", align 8
  %update_elem2 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_c, ptr %"@c_key", ptr %"@c_val", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@c_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@c_key")
  %24 = load i64, ptr %"$x", align 8
  %25 = inttoptr i64 %24 to ptr
  %26 = call ptr @llvm.preserve.static.offset(ptr %25)
  %27 = getelementptr i8, ptr %26, i64 24
  %28 = load volatile i64, ptr %27, align 8
  %29 = inttoptr i64 %28 to ptr
  %30 = call ptr @llvm.preserve.static.offset(ptr %29)
  %31 = getelementptr i8, ptr %30, i64 0
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"struct c.c")
  %probe_read_kernel = call i64 inttoptr (i64 113 to ptr)(ptr %"struct c.c", i32 1, ptr %31)
  %32 = load i8, ptr %"struct c.c", align 1
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"struct c.c")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@d_key")
  store i64 0, ptr %"@d_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@d_val")
  %33 = sext i8 %32 to i64
  store i64 %33, ptr %"@d_val", align 8
  %update_elem3 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_d, ptr %"@d_key", ptr %"@d_val", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@d_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@d_key")
  %34 = load i64, ptr %"$x", align 8
  %35 = inttoptr i64 %34 to ptr
  %36 = call ptr @llvm.preserve.static.offset(ptr %35)
  %37 = getelementptr i8, ptr %36, i64 32
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"struct x.e")
  %probe_read_kernel4 = call i64 inttoptr (i64 113 to ptr)(ptr %"struct x.e", i32 4, ptr %37)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@e_key")
  store i64 0, ptr %"@e_key", align 8
  %update_elem5 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_e, ptr %"@e_key", ptr %"struct x.e", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@e_key")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"struct x.e")
  ret i64 0
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare ptr @llvm.preserve.static.offset(ptr readnone %0) #2

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #2 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }

!llvm.dbg.cu = !{!60}
!llvm.module.flags = !{!62}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "LICENSE", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 32, elements: !5)
!4 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!5 = !{!6}
!6 = !DISubrange(count: 4, lowerBound: 0)
!7 = !DIGlobalVariableExpression(var: !8, expr: !DIExpression())
!8 = distinct !DIGlobalVariable(name: "AT_a", linkageName: "global", scope: !2, file: !2, type: !9, isLocal: false, isDefinition: true)
!9 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !10)
!10 = !{!11, !17, !18, !21}
!11 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !12, size: 64)
!12 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !13, size: 64)
!13 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 32, elements: !15)
!14 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!15 = !{!16}
!16 = !DISubrange(count: 1, lowerBound: 0)
!17 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !12, size: 64, offset: 64)
!18 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !19, size: 64, offset: 128)
!19 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !20, size: 64)
!20 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!21 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !19, size: 64, offset: 192)
!22 = !DIGlobalVariableExpression(var: !23, expr: !DIExpression())
!23 = distinct !DIGlobalVariable(name: "AT_b", linkageName: "global", scope: !2, file: !2, type: !9, isLocal: false, isDefinition: true)
!24 = !DIGlobalVariableExpression(var: !25, expr: !DIExpression())
!25 = distinct !DIGlobalVariable(name: "AT_c", linkageName: "global", scope: !2, file: !2, type: !9, isLocal: false, isDefinition: true)
!26 = !DIGlobalVariableExpression(var: !27, expr: !DIExpression())
!27 = distinct !DIGlobalVariable(name: "AT_d", linkageName: "global", scope: !2, file: !2, type: !9, isLocal: false, isDefinition: true)
!28 = !DIGlobalVariableExpression(var: !29, expr: !DIExpression())
!29 = distinct !DIGlobalVariable(name: "AT_e", linkageName: "global", scope: !2, file: !2, type: !30, isLocal: false, isDefinition: true)
!30 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !31)
!31 = !{!11, !17, !18, !32}
!32 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !33, size: 64, offset: 192)
!33 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !3, size: 64)
!34 = !DIGlobalVariableExpression(var: !35, expr: !DIExpression())
!35 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !36, isLocal: false, isDefinition: true)
!36 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !37)
!37 = !{!38, !43}
!38 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !39, size: 64)
!39 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !40, size: 64)
!40 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 864, elements: !41)
!41 = !{!42}
!42 = !DISubrange(count: 27, lowerBound: 0)
!43 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !44, size: 64, offset: 64)
!44 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !45, size: 64)
!45 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 8388608, elements: !46)
!46 = !{!47}
!47 = !DISubrange(count: 262144, lowerBound: 0)
!48 = !DIGlobalVariableExpression(var: !49, expr: !DIExpression())
!49 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !50, isLocal: false, isDefinition: true)
!50 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !51)
!51 = !{!52, !17, !57, !21}
!52 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !53, size: 64)
!53 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !54, size: 64)
!54 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 64, elements: !55)
!55 = !{!56}
!56 = !DISubrange(count: 2, lowerBound: 0)
!57 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !58, size: 64, offset: 128)
!58 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !59, size: 64)
!59 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!60 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !61)
!61 = !{!0, !7, !22, !24, !26, !28, !34, !48}
!62 = !{i32 2, !"Debug Info Version", i32 3}
!63 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !64, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !60, retainedNodes: !67)
!64 = !DISubroutineType(types: !65)
!65 = !{!20, !66}
!66 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!67 = !{!68}
!68 = !DILocalVariable(name: "ctx", arg: 1, scope: !63, file: !2, type: !66)
