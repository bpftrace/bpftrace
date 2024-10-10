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

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_a = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@AT_b = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !22
@AT_c = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !24
@AT_d = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !26
@AT_e = dso_local global %"struct map_t.3" zeroinitializer, section ".maps", !dbg !28
@ringbuf = dso_local global %"struct map_t.4" zeroinitializer, section ".maps", !dbg !38
@event_loss_counter = dso_local global %"struct map_t.5" zeroinitializer, section ".maps", !dbg !52
@max_cpu_id = dso_local externally_initialized constant i64 zeroinitializer, section ".rodata", !dbg !54
@write_map_val_buf = dso_local externally_initialized global [1 x [1 x [8 x i8]]] zeroinitializer, section ".data.write_map_val_buf", !dbg !56

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(ptr %0) section "s_kprobe_f_1" !dbg !66 {
entry:
  %"@e_key" = alloca i64, align 8
  %"struct x.e" = alloca [4 x i8], align 1
  %"@d_key" = alloca i64, align 8
  %"struct c.c" = alloca i8, align 1
  %"@c_key" = alloca i64, align 8
  %"@b_key" = alloca i64, align 8
  %"@a_key" = alloca i64, align 8
  %"$x" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$x")
  store i64 0, ptr %"$x", align 8
  %1 = ptrtoint ptr %0 to i64
  store i64 %1, ptr %"$x", align 8
  %2 = load i64, ptr %"$x", align 8
  %3 = add i64 %2, 0
  %4 = inttoptr i64 %3 to ptr
  %5 = load volatile i64, ptr %4, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@a_key")
  store i64 0, ptr %"@a_key", align 8
  %get_cpu_id = call i64 inttoptr (i64 8 to ptr)()
  %6 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded = and i64 %get_cpu_id, %6
  %7 = getelementptr [1 x [1 x [8 x i8]]], ptr @write_map_val_buf, i64 0, i64 %cpu.id.bounded, i64 0, i64 0
  store i64 %5, ptr %7, align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_a, ptr %"@a_key", ptr %7, i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@a_key")
  %8 = load i64, ptr %"$x", align 8
  %9 = add i64 %8, 8
  %10 = add i64 %9, 0
  %11 = inttoptr i64 %10 to ptr
  %12 = load volatile i16, ptr %11, align 2
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@b_key")
  store i64 0, ptr %"@b_key", align 8
  %get_cpu_id1 = call i64 inttoptr (i64 8 to ptr)()
  %13 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded2 = and i64 %get_cpu_id1, %13
  %14 = getelementptr [1 x [1 x [8 x i8]]], ptr @write_map_val_buf, i64 0, i64 %cpu.id.bounded2, i64 0, i64 0
  %15 = sext i16 %12 to i64
  store i64 %15, ptr %14, align 8
  %update_elem3 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_b, ptr %"@b_key", ptr %14, i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@b_key")
  %16 = load i64, ptr %"$x", align 8
  %17 = add i64 %16, 16
  %18 = add i64 %17, 0
  %19 = inttoptr i64 %18 to ptr
  %20 = load volatile i8, ptr %19, align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@c_key")
  store i64 0, ptr %"@c_key", align 8
  %get_cpu_id4 = call i64 inttoptr (i64 8 to ptr)()
  %21 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded5 = and i64 %get_cpu_id4, %21
  %22 = getelementptr [1 x [1 x [8 x i8]]], ptr @write_map_val_buf, i64 0, i64 %cpu.id.bounded5, i64 0, i64 0
  %23 = sext i8 %20 to i64
  store i64 %23, ptr %22, align 8
  %update_elem6 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_c, ptr %"@c_key", ptr %22, i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@c_key")
  %24 = load i64, ptr %"$x", align 8
  %25 = add i64 %24, 24
  %26 = inttoptr i64 %25 to ptr
  %27 = load volatile i64, ptr %26, align 8
  %28 = add i64 %27, 0
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"struct c.c")
  %probe_read_kernel = call i64 inttoptr (i64 113 to ptr)(ptr %"struct c.c", i32 1, i64 %28)
  %29 = load i8, ptr %"struct c.c", align 1
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"struct c.c")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@d_key")
  store i64 0, ptr %"@d_key", align 8
  %get_cpu_id7 = call i64 inttoptr (i64 8 to ptr)()
  %30 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded8 = and i64 %get_cpu_id7, %30
  %31 = getelementptr [1 x [1 x [8 x i8]]], ptr @write_map_val_buf, i64 0, i64 %cpu.id.bounded8, i64 0, i64 0
  %32 = sext i8 %29 to i64
  store i64 %32, ptr %31, align 8
  %update_elem9 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_d, ptr %"@d_key", ptr %31, i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@d_key")
  %33 = load i64, ptr %"$x", align 8
  %34 = add i64 %33, 32
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"struct x.e")
  %probe_read_kernel10 = call i64 inttoptr (i64 113 to ptr)(ptr %"struct x.e", i32 4, i64 %34)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@e_key")
  store i64 0, ptr %"@e_key", align 8
  %update_elem11 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_e, ptr %"@e_key", ptr %"struct x.e", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@e_key")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"struct x.e")
  ret i64 0
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }

!llvm.dbg.cu = !{!63}
!llvm.module.flags = !{!65}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "AT_a", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !4)
!4 = !{!5, !11, !16, !19}
!5 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !6, size: 64)
!6 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !7, size: 64)
!7 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !9)
!8 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!9 = !{!10}
!10 = !DISubrange(count: 2, lowerBound: 0)
!11 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !12, size: 64, offset: 64)
!12 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !13, size: 64)
!13 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 32, elements: !14)
!14 = !{!15}
!15 = !DISubrange(count: 1, lowerBound: 0)
!16 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !17, size: 64, offset: 128)
!17 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !18, size: 64)
!18 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!19 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !20, size: 64, offset: 192)
!20 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !21, size: 64)
!21 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!22 = !DIGlobalVariableExpression(var: !23, expr: !DIExpression())
!23 = distinct !DIGlobalVariable(name: "AT_b", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!24 = !DIGlobalVariableExpression(var: !25, expr: !DIExpression())
!25 = distinct !DIGlobalVariable(name: "AT_c", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!26 = !DIGlobalVariableExpression(var: !27, expr: !DIExpression())
!27 = distinct !DIGlobalVariable(name: "AT_d", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!28 = !DIGlobalVariableExpression(var: !29, expr: !DIExpression())
!29 = distinct !DIGlobalVariable(name: "AT_e", linkageName: "global", scope: !2, file: !2, type: !30, isLocal: false, isDefinition: true)
!30 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !31)
!31 = !{!5, !11, !16, !32}
!32 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !33, size: 64, offset: 192)
!33 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !34, size: 64)
!34 = !DICompositeType(tag: DW_TAG_array_type, baseType: !35, size: 32, elements: !36)
!35 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!36 = !{!37}
!37 = !DISubrange(count: 4, lowerBound: 0)
!38 = !DIGlobalVariableExpression(var: !39, expr: !DIExpression())
!39 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !40, isLocal: false, isDefinition: true)
!40 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !41)
!41 = !{!42, !47}
!42 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !43, size: 64)
!43 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !44, size: 64)
!44 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !45)
!45 = !{!46}
!46 = !DISubrange(count: 27, lowerBound: 0)
!47 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !48, size: 64, offset: 64)
!48 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !49, size: 64)
!49 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !50)
!50 = !{!51}
!51 = !DISubrange(count: 262144, lowerBound: 0)
!52 = !DIGlobalVariableExpression(var: !53, expr: !DIExpression())
!53 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!54 = !DIGlobalVariableExpression(var: !55, expr: !DIExpression())
!55 = distinct !DIGlobalVariable(name: "max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !21, isLocal: false, isDefinition: true)
!56 = !DIGlobalVariableExpression(var: !57, expr: !DIExpression())
!57 = distinct !DIGlobalVariable(name: "write_map_val_buf", linkageName: "global", scope: !2, file: !2, type: !58, isLocal: false, isDefinition: true)
!58 = !DICompositeType(tag: DW_TAG_array_type, baseType: !59, size: 64, elements: !14)
!59 = !DICompositeType(tag: DW_TAG_array_type, baseType: !60, size: 64, elements: !14)
!60 = !DICompositeType(tag: DW_TAG_array_type, baseType: !35, size: 64, elements: !61)
!61 = !{!62}
!62 = !DISubrange(count: 8, lowerBound: 0)
!63 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !64)
!64 = !{!0, !22, !24, !26, !28, !38, !52, !54, !56}
!65 = !{i32 2, !"Debug Info Version", i32 3}
!66 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !67, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !63, retainedNodes: !70)
!67 = !DISubroutineType(types: !68)
!68 = !{!21, !69}
!69 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !35, size: 64)
!70 = !{!71}
!71 = !DILocalVariable(name: "ctx", arg: 1, scope: !66, file: !2, type: !69)
