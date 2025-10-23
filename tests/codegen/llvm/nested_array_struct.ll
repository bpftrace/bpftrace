; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%"struct map_internal_repr_t" = type { ptr, ptr, ptr, ptr }
%"struct map_internal_repr_t.163" = type { ptr, ptr, ptr, ptr }
%"struct map_internal_repr_t.164" = type { ptr, ptr }
%runtime_error_t = type <{ i64, i64, i32 }>

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@AT_ = dso_local global %"struct map_internal_repr_t" zeroinitializer, section ".maps", !dbg !7
@AT_bar = dso_local global %"struct map_internal_repr_t.163" zeroinitializer, section ".maps", !dbg !22
@ringbuf = dso_local global %"struct map_internal_repr_t.164" zeroinitializer, section ".maps", !dbg !37
@__bt__event_loss_counter = dso_local externally_initialized global [1 x [1 x i64]] zeroinitializer, section ".data.event_loss_counter", !dbg !51
@__bt__max_cpu_id = dso_local externally_initialized constant i64 0, section ".rodata", !dbg !55

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

; Function Attrs: nounwind
define i64 @kprobe_f_1(ptr %0) #0 section "s_kprobe_f_1" !dbg !61 {
entry:
  %"@_val" = alloca i64, align 8
  %"@_key" = alloca i64, align 8
  %runtime_error_t4 = alloca %runtime_error_t, align 8
  %runtime_error_t = alloca %runtime_error_t, align 8
  %lookup_elem_val = alloca [2 x [2 x [4 x i8]]], align 1
  %"@bar_key1" = alloca i64, align 8
  %"@bar_val" = alloca [2 x [2 x [4 x i8]]], align 1
  %"@bar_key" = alloca i64, align 8
  %1 = call ptr @llvm.preserve.static.offset(ptr %0)
  %2 = getelementptr i8, ptr %1, i64 112
  %arg0 = load volatile i64, ptr %2, align 8
  %3 = inttoptr i64 %arg0 to ptr
  %4 = call ptr @llvm.preserve.static.offset(ptr %3)
  %5 = getelementptr i8, ptr %4, i64 0
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@bar_key")
  store i64 42, ptr %"@bar_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@bar_val")
  %probe_read_kernel = call i64 inttoptr (i64 113 to ptr)(ptr %"@bar_val", i32 16, ptr %5)
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_bar, ptr %"@bar_key", ptr %"@bar_val", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@bar_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@bar_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@bar_key1")
  store i64 42, ptr %"@bar_key1", align 8
  %lookup_elem = call ptr inttoptr (i64 1 to ptr)(ptr @AT_bar, ptr %"@bar_key1")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_elem_val)
  %map_lookup_cond = icmp ne ptr %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %lookup_elem_val, ptr align 1 %lookup_elem, i64 16, i1 false)
  br label %lookup_merge

lookup_failure:                                   ; preds = %entry
  call void @llvm.memset.p0.i64(ptr align 1 %lookup_elem_val, i8 0, i64 16, i1 false)
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@bar_key1")
  br i1 false, label %is_oob, label %oob_merge

is_oob:                                           ; preds = %lookup_merge
  call void @llvm.lifetime.start.p0(i64 -1, ptr %runtime_error_t)
  %6 = getelementptr %runtime_error_t, ptr %runtime_error_t, i64 0, i32 0
  store i64 30006, ptr %6, align 8
  %7 = getelementptr %runtime_error_t, ptr %runtime_error_t, i64 0, i32 1
  store i64 0, ptr %7, align 8
  %8 = getelementptr %runtime_error_t, ptr %runtime_error_t, i64 0, i32 2
  store i64 0, ptr %8, align 8
  %ringbuf_output = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %runtime_error_t, i64 20, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

oob_merge:                                        ; preds = %counter_merge, %lookup_merge
  %9 = getelementptr [2 x [2 x [4 x i8]]], ptr %lookup_elem_val, i32 0, i64 0
  br i1 false, label %is_oob2, label %oob_merge3

event_loss_counter:                               ; preds = %is_oob
  %get_cpu_id = call i64 inttoptr (i64 8 to ptr)() #5
  %10 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded = and i64 %get_cpu_id, %10
  %11 = getelementptr [1 x [1 x i64]], ptr @__bt__event_loss_counter, i64 0, i64 %cpu.id.bounded, i64 0
  %12 = load i64, ptr %11, align 8
  %13 = add i64 %12, 1
  store i64 %13, ptr %11, align 8
  br label %counter_merge

counter_merge:                                    ; preds = %event_loss_counter, %is_oob
  call void @llvm.lifetime.end.p0(i64 -1, ptr %runtime_error_t)
  br label %oob_merge

is_oob2:                                          ; preds = %oob_merge
  call void @llvm.lifetime.start.p0(i64 -1, ptr %runtime_error_t4)
  %14 = getelementptr %runtime_error_t, ptr %runtime_error_t4, i64 0, i32 0
  store i64 30006, ptr %14, align 8
  %15 = getelementptr %runtime_error_t, ptr %runtime_error_t4, i64 0, i32 1
  store i64 1, ptr %15, align 8
  %16 = getelementptr %runtime_error_t, ptr %runtime_error_t4, i64 0, i32 2
  store i64 0, ptr %16, align 8
  %ringbuf_output5 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %runtime_error_t4, i64 20, i64 0)
  %ringbuf_loss8 = icmp slt i64 %ringbuf_output5, 0
  br i1 %ringbuf_loss8, label %event_loss_counter6, label %counter_merge7

oob_merge3:                                       ; preds = %counter_merge7, %oob_merge
  %17 = getelementptr [2 x [4 x i8]], ptr %9, i32 0, i64 1
  %18 = getelementptr [4 x i8], ptr %17, i32 0, i64 0
  %19 = load volatile i32, ptr %18, align 4
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_elem_val)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@_key")
  store i64 0, ptr %"@_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@_val")
  %20 = sext i32 %19 to i64
  store i64 %20, ptr %"@_val", align 8
  %update_elem11 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_, ptr %"@_key", ptr %"@_val", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@_key")
  ret i64 0

event_loss_counter6:                              ; preds = %is_oob2
  %get_cpu_id9 = call i64 inttoptr (i64 8 to ptr)() #5
  %21 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded10 = and i64 %get_cpu_id9, %21
  %22 = getelementptr [1 x [1 x i64]], ptr @__bt__event_loss_counter, i64 0, i64 %cpu.id.bounded10, i64 0
  %23 = load i64, ptr %22, align 8
  %24 = add i64 %23, 1
  store i64 %24, ptr %22, align 8
  br label %counter_merge7

counter_merge7:                                   ; preds = %event_loss_counter6, %is_oob2
  call void @llvm.lifetime.end.p0(i64 -1, ptr %runtime_error_t4)
  br label %oob_merge3
}

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare ptr @llvm.preserve.static.offset(ptr readnone %0) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #2

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #2

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: readwrite)
declare void @llvm.memcpy.p0.p0.i64(ptr noalias nocapture writeonly %0, ptr noalias nocapture readonly %1, i64 %2, i1 immarg %3) #3

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #4

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }
attributes #2 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #3 = { nocallback nofree nounwind willreturn memory(argmem: readwrite) }
attributes #4 = { nocallback nofree nounwind willreturn memory(argmem: write) }
attributes #5 = { memory(none) }

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
!8 = distinct !DIGlobalVariable(name: "AT_", linkageName: "global", scope: !2, file: !2, type: !9, isLocal: false, isDefinition: true)
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
!23 = distinct !DIGlobalVariable(name: "AT_bar", linkageName: "global", scope: !2, file: !2, type: !24, isLocal: false, isDefinition: true)
!24 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !25)
!25 = !{!11, !26, !18, !31}
!26 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !27, size: 64, offset: 64)
!27 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !28, size: 64)
!28 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 131072, elements: !29)
!29 = !{!30}
!30 = !DISubrange(count: 4096, lowerBound: 0)
!31 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !32, size: 64, offset: 192)
!32 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !33, size: 64)
!33 = !DICompositeType(tag: DW_TAG_array_type, baseType: !34, size: 128, elements: !35)
!34 = !DICompositeType(tag: DW_TAG_array_type, baseType: !3, size: 64, elements: !35)
!35 = !{!36}
!36 = !DISubrange(count: 2, lowerBound: 0)
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
!58 = !{!0, !7, !22, !37, !51, !55}
!59 = !{i32 2, !"Debug Info Version", i32 3}
!60 = !{i32 7, !"uwtable", i32 0}
!61 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !62, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !57, retainedNodes: !65)
!62 = !DISubroutineType(types: !63)
!63 = !{!20, !64}
!64 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!65 = !{!66}
!66 = !DILocalVariable(name: "ctx", arg: 1, scope: !61, file: !2, type: !64)
