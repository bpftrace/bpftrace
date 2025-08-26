; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%"struct map_internal_repr_t" = type { ptr, ptr, ptr, ptr }
%"struct map_internal_repr_t.0" = type { ptr, ptr, ptr, ptr }
%"struct map_internal_repr_t.1" = type { ptr, ptr, ptr, ptr }
%"struct map_internal_repr_t.2" = type { ptr, ptr, ptr, ptr }
%"struct map_internal_repr_t.3" = type { ptr, ptr, ptr, ptr }
%"struct map_internal_repr_t.4" = type { ptr, ptr }
%runtime_error_t = type <{ i64, i64, i32 }>

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@AT_a = dso_local global %"struct map_internal_repr_t" zeroinitializer, section ".maps", !dbg !7
@AT_b = dso_local global %"struct map_internal_repr_t.0" zeroinitializer, section ".maps", !dbg !22
@AT_c = dso_local global %"struct map_internal_repr_t.1" zeroinitializer, section ".maps", !dbg !24
@AT_d = dso_local global %"struct map_internal_repr_t.2" zeroinitializer, section ".maps", !dbg !26
@AT_e = dso_local global %"struct map_internal_repr_t.3" zeroinitializer, section ".maps", !dbg !28
@ringbuf = dso_local global %"struct map_internal_repr_t.4" zeroinitializer, section ".maps", !dbg !37
@__bt__event_loss_counter = dso_local externally_initialized global [1 x [1 x i64]] zeroinitializer, section ".data.event_loss_counter", !dbg !51
@__bt__max_cpu_id = dso_local externally_initialized constant i64 0, section ".rodata", !dbg !55

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

; Function Attrs: nounwind
define i64 @kprobe_f_1(ptr %0) #0 section "s_kprobe_f_1" !dbg !61 {
entry:
  %"@e_key" = alloca i64, align 8
  %"struct x.e" = alloca [5 x i8], align 1
  %"@d_val" = alloca i64, align 8
  %"@d_key" = alloca i64, align 8
  %"struct c.c" = alloca i8, align 1
  %"@c_val" = alloca i64, align 8
  %"@c_key" = alloca i64, align 8
  %"@b_val" = alloca i64, align 8
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
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@a_key")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@a_val")
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
  %16 = sext i16 %15 to i64
  store i64 %16, ptr %"@b_val", align 8
  %update_elem1 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_b, ptr %"@b_key", ptr %"@b_val", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@b_key")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@b_val")
  %17 = load ptr, ptr %"$x", align 8
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
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@c_key")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@c_val")
  %24 = load ptr, ptr %"$x", align 8
  %25 = call ptr @llvm.preserve.static.offset(ptr %24)
  %26 = getelementptr i8, ptr %25, i64 24
  %27 = load volatile ptr, ptr %26, align 8
  %28 = call ptr @llvm.preserve.static.offset(ptr %27)
  %29 = getelementptr i8, ptr %28, i64 0
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"struct c.c")
  %probe_read_kernel = call i64 inttoptr (i64 113 to ptr)(ptr %"struct c.c", i32 1, ptr %29)
  %30 = load i8, ptr %"struct c.c", align 1
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"struct c.c")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@d_key")
  store i64 0, ptr %"@d_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@d_val")
  %31 = sext i8 %30 to i64
  store i64 %31, ptr %"@d_val", align 8
  %update_elem3 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_d, ptr %"@d_key", ptr %"@d_val", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@d_key")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@d_val")
  %32 = load ptr, ptr %"$x", align 8
  %33 = call ptr @llvm.preserve.static.offset(ptr %32)
  %34 = getelementptr i8, ptr %33, i64 32
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"struct x.e")
  %probe_read_kernel4 = call i64 inttoptr (i64 113 to ptr)(ptr %"struct x.e", i32 5, ptr %34)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@e_key")
  store i64 0, ptr %"@e_key", align 8
  %update_elem5 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_e, ptr %"@e_key", ptr %"struct x.e", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@e_key")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"struct x.e")
  ret i64 0

event_loss_counter:                               ; preds = %is_oob
  %get_cpu_id = call i64 inttoptr (i64 8 to ptr)() #3
  %35 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded = and i64 %get_cpu_id, %35
  %36 = getelementptr [1 x [1 x i64]], ptr @__bt__event_loss_counter, i64 0, i64 %cpu.id.bounded, i64 0
  %37 = load i64, ptr %36, align 8
  %38 = add i64 %37, 1
  store i64 %38, ptr %36, align 8
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

!llvm.dbg.cu = !{!57}
!llvm.module.flags = !{!59, !60}

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
!33 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !34, size: 64)
!34 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 40, elements: !35)
!35 = !{!36}
!36 = !DISubrange(count: 5, lowerBound: 0)
!37 = !DIGlobalVariableExpression(var: !38, expr: !DIExpression())
!38 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !39, isLocal: false, isDefinition: true)
!39 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !40)
!40 = !{!41, !46}
!41 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !42, size: 64)
!42 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !43, size: 64)
!43 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 864, elements: !44)
!44 = !{!45}
!45 = !DISubrange(count: 27, lowerBound: 0)
!46 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !47, size: 64, offset: 64)
!47 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !48, size: 64)
!48 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 8388608, elements: !49)
!49 = !{!50}
!50 = !DISubrange(count: 262144, lowerBound: 0)
!51 = !DIGlobalVariableExpression(var: !52, expr: !DIExpression())
!52 = distinct !DIGlobalVariable(name: "__bt__event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !53, isLocal: false, isDefinition: true)
!53 = !DICompositeType(tag: DW_TAG_array_type, baseType: !54, size: 64, elements: !15)
!54 = !DICompositeType(tag: DW_TAG_array_type, baseType: !20, size: 64, elements: !15)
!55 = !DIGlobalVariableExpression(var: !56, expr: !DIExpression())
!56 = distinct !DIGlobalVariable(name: "__bt__max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !20, isLocal: false, isDefinition: true)
!57 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !58)
!58 = !{!0, !7, !22, !24, !26, !28, !37, !51, !55}
!59 = !{i32 2, !"Debug Info Version", i32 3}
!60 = !{i32 7, !"uwtable", i32 0}
!61 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !62, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !57, retainedNodes: !65)
!62 = !DISubroutineType(types: !63)
!63 = !{!20, !64}
!64 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!65 = !{!66}
!66 = !DILocalVariable(name: "ctx", arg: 1, scope: !61, file: !2, type: !64)
