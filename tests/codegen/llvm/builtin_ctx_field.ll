; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%"struct map_internal_repr_t" = type { ptr, ptr, ptr, ptr }
%"struct map_internal_repr_t.163" = type { ptr, ptr, ptr, ptr }
%"struct map_internal_repr_t.164" = type { ptr, ptr, ptr, ptr }
%"struct map_internal_repr_t.165" = type { ptr, ptr, ptr, ptr }
%"struct map_internal_repr_t.166" = type { ptr, ptr, ptr, ptr }
%"struct map_internal_repr_t.167" = type { ptr, ptr }
%runtime_error_t = type <{ i64, i64, i32 }>

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@AT_a = dso_local global %"struct map_internal_repr_t" zeroinitializer, section ".maps", !dbg !7
@AT_b = dso_local global %"struct map_internal_repr_t.163" zeroinitializer, section ".maps", !dbg !22
@AT_c = dso_local global %"struct map_internal_repr_t.164" zeroinitializer, section ".maps", !dbg !29
@AT_d = dso_local global %"struct map_internal_repr_t.165" zeroinitializer, section ".maps", !dbg !35
@AT_e = dso_local global %"struct map_internal_repr_t.166" zeroinitializer, section ".maps", !dbg !37
@ringbuf = dso_local global %"struct map_internal_repr_t.167" zeroinitializer, section ".maps", !dbg !46
@__bt__event_loss_counter = dso_local externally_initialized global [1 x [1 x i64]] zeroinitializer, section ".data.event_loss_counter", !dbg !60
@__bt__max_cpu_id = dso_local externally_initialized constant i64 0, section ".rodata", !dbg !64

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

; Function Attrs: nounwind
define i64 @kprobe_f_1(ptr %0) #0 section "s_kprobe_f_1" !dbg !70 {
entry:
  %"@e_key" = alloca i64, align 8
  %"struct x.e" = alloca [5 x i8], align 1
  %"@d_val" = alloca i8, align 1
  %"@d_key" = alloca i64, align 8
  %"struct c.c" = alloca i8, align 1
  %"@c_val" = alloca i8, align 1
  %"@c_key" = alloca i64, align 8
  %"@b_val" = alloca i16, align 2
  %"@b_key" = alloca i64, align 8
  %runtime_error_t = alloca %runtime_error_t, align 8
  %"@a_val" = alloca i64, align 8
  %"@a_key" = alloca i64, align 8
  %"$x" = alloca ptr, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$x")
  store i0 0, ptr %"$x", align 1
  store ptr %0, ptr %"$x", align 8
  %1 = load ptr, ptr %"$x", align 8
  %2 = call ptr @llvm.preserve.static.offset(ptr %1)
  %3 = getelementptr i8, ptr %2, i64 0
  %4 = load volatile i64, ptr %3, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@a_key")
  store i64 0, ptr %"@a_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@a_val")
  store i64 %4, ptr %"@a_val", align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_a, ptr %"@a_key", ptr %"@a_val", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@a_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@a_key")
  %5 = load ptr, ptr %"$x", align 8
  %6 = call ptr @llvm.preserve.static.offset(ptr %5)
  %7 = getelementptr i8, ptr %6, i64 8
  br i1 false, label %is_oob, label %oob_merge

is_oob:                                           ; preds = %entry
  call void @llvm.lifetime.start.p0(i64 -1, ptr %runtime_error_t)
  %8 = getelementptr %runtime_error_t, ptr %runtime_error_t, i64 0, i32 0
  store i64 30006, ptr %8, align 8
  %9 = getelementptr %runtime_error_t, ptr %runtime_error_t, i64 0, i32 1
  store i64 0, ptr %9, align 8
  %10 = getelementptr %runtime_error_t, ptr %runtime_error_t, i64 0, i32 2
  store i64 0, ptr %10, align 8
  %ringbuf_output = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %runtime_error_t, i64 20, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

oob_merge:                                        ; preds = %counter_merge, %entry
  %11 = ptrtoint ptr %7 to i64
  %12 = inttoptr i64 %11 to ptr
  %13 = call ptr @llvm.preserve.static.offset(ptr %12)
  %14 = getelementptr i8, ptr %13, i64 0
  %15 = load volatile i16, ptr %14, align 2
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@b_key")
  store i64 0, ptr %"@b_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@b_val")
  store i16 %15, ptr %"@b_val", align 2
  %update_elem1 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_b, ptr %"@b_key", ptr %"@b_val", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@b_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@b_key")
  %16 = load ptr, ptr %"$x", align 8
  %17 = call ptr @llvm.preserve.static.offset(ptr %16)
  %18 = getelementptr i8, ptr %17, i64 16
  %19 = call ptr @llvm.preserve.static.offset(ptr %18)
  %20 = getelementptr i8, ptr %19, i64 0
  %21 = load volatile i8, ptr %20, align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@c_key")
  store i64 0, ptr %"@c_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@c_val")
  store i8 %21, ptr %"@c_val", align 1
  %update_elem2 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_c, ptr %"@c_key", ptr %"@c_val", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@c_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@c_key")
  %22 = load ptr, ptr %"$x", align 8
  %23 = call ptr @llvm.preserve.static.offset(ptr %22)
  %24 = getelementptr i8, ptr %23, i64 24
  %25 = load volatile ptr, ptr %24, align 8
  %26 = call ptr @llvm.preserve.static.offset(ptr %25)
  %27 = getelementptr i8, ptr %26, i64 0
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"struct c.c")
  %probe_read_kernel = call i64 inttoptr (i64 113 to ptr)(ptr %"struct c.c", i32 1, ptr %27)
  %28 = load i8, ptr %"struct c.c", align 1
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"struct c.c")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@d_key")
  store i64 0, ptr %"@d_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@d_val")
  store i8 %28, ptr %"@d_val", align 1
  %update_elem3 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_d, ptr %"@d_key", ptr %"@d_val", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@d_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@d_key")
  %29 = load ptr, ptr %"$x", align 8
  %30 = call ptr @llvm.preserve.static.offset(ptr %29)
  %31 = getelementptr i8, ptr %30, i64 32
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"struct x.e")
  %probe_read_kernel4 = call i64 inttoptr (i64 113 to ptr)(ptr %"struct x.e", i32 5, ptr %31)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@e_key")
  store i64 0, ptr %"@e_key", align 8
  %update_elem5 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_e, ptr %"@e_key", ptr %"struct x.e", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@e_key")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"struct x.e")
  ret i64 0

event_loss_counter:                               ; preds = %is_oob
  %get_cpu_id = call i64 inttoptr (i64 8 to ptr)() #3
  %32 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded = and i64 %get_cpu_id, %32
  %33 = getelementptr [1 x [1 x i64]], ptr @__bt__event_loss_counter, i64 0, i64 %cpu.id.bounded, i64 0
  %34 = load i64, ptr %33, align 8
  %35 = add i64 %34, 1
  store i64 %35, ptr %33, align 8
  br label %counter_merge

counter_merge:                                    ; preds = %event_loss_counter, %is_oob
  call void @llvm.lifetime.end.p0(i64 -1, ptr %runtime_error_t)
  br label %oob_merge
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
attributes #3 = { memory(none) }

!llvm.dbg.cu = !{!66}
!llvm.module.flags = !{!68, !69}

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
!23 = distinct !DIGlobalVariable(name: "AT_b", linkageName: "global", scope: !2, file: !2, type: !24, isLocal: false, isDefinition: true)
!24 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !25)
!25 = !{!11, !17, !18, !26}
!26 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !27, size: 64, offset: 192)
!27 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !28, size: 64)
!28 = !DIBasicType(name: "int16", size: 16, encoding: DW_ATE_signed)
!29 = !DIGlobalVariableExpression(var: !30, expr: !DIExpression())
!30 = distinct !DIGlobalVariable(name: "AT_c", linkageName: "global", scope: !2, file: !2, type: !31, isLocal: false, isDefinition: true)
!31 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !32)
!32 = !{!11, !17, !18, !33}
!33 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !34, size: 64, offset: 192)
!34 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!35 = !DIGlobalVariableExpression(var: !36, expr: !DIExpression())
!36 = distinct !DIGlobalVariable(name: "AT_d", linkageName: "global", scope: !2, file: !2, type: !31, isLocal: false, isDefinition: true)
!37 = !DIGlobalVariableExpression(var: !38, expr: !DIExpression())
!38 = distinct !DIGlobalVariable(name: "AT_e", linkageName: "global", scope: !2, file: !2, type: !39, isLocal: false, isDefinition: true)
!39 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !40)
!40 = !{!11, !17, !18, !41}
!41 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !42, size: 64, offset: 192)
!42 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !43, size: 64)
!43 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 40, elements: !44)
!44 = !{!45}
!45 = !DISubrange(count: 5, lowerBound: 0)
!46 = !DIGlobalVariableExpression(var: !47, expr: !DIExpression())
!47 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !48, isLocal: false, isDefinition: true)
!48 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !49)
!49 = !{!50, !55}
!50 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !51, size: 64)
!51 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !52, size: 64)
!52 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 864, elements: !53)
!53 = !{!54}
!54 = !DISubrange(count: 27, lowerBound: 0)
!55 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !56, size: 64, offset: 64)
!56 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !57, size: 64)
!57 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 8388608, elements: !58)
!58 = !{!59}
!59 = !DISubrange(count: 262144, lowerBound: 0)
!60 = !DIGlobalVariableExpression(var: !61, expr: !DIExpression())
!61 = distinct !DIGlobalVariable(name: "__bt__event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !62, isLocal: false, isDefinition: true)
!62 = !DICompositeType(tag: DW_TAG_array_type, baseType: !63, size: 64, elements: !15)
!63 = !DICompositeType(tag: DW_TAG_array_type, baseType: !20, size: 64, elements: !15)
!64 = !DIGlobalVariableExpression(var: !65, expr: !DIExpression())
!65 = distinct !DIGlobalVariable(name: "__bt__max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !20, isLocal: false, isDefinition: true)
!66 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !67)
!67 = !{!0, !7, !22, !29, !35, !37, !46, !60, !64}
!68 = !{i32 2, !"Debug Info Version", i32 3}
!69 = !{i32 7, !"uwtable", i32 0}
!70 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !71, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !66, retainedNodes: !73)
!71 = !DISubroutineType(types: !72)
!72 = !{!20, !34}
!73 = !{!74}
!74 = !DILocalVariable(name: "ctx", arg: 1, scope: !70, file: !2, type: !34)
