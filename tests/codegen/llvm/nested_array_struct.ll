; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%"struct map_internal_repr_t" = type { ptr, ptr, ptr, ptr }
%"struct map_internal_repr_t.616" = type { ptr, ptr, ptr, ptr }
%"struct map_internal_repr_t.617" = type { ptr, ptr }
%runtime_error_t = type <{ i64, i64, i32 }>

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@AT_ = dso_local global %"struct map_internal_repr_t" zeroinitializer, section ".maps", !dbg !7
@AT_bar = dso_local global %"struct map_internal_repr_t.616" zeroinitializer, section ".maps", !dbg !24
@ringbuf = dso_local global %"struct map_internal_repr_t.617" zeroinitializer, section ".maps", !dbg !41
@__bt__event_loss_counter = dso_local externally_initialized global [1 x [1 x i64]] zeroinitializer, section ".data.event_loss_counter", !dbg !55
@__bt__max_cpu_id = dso_local externally_initialized constant i64 0, section ".rodata", !dbg !59

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

; Function Attrs: nounwind
define i64 @kprobe_f_1(ptr %0) #0 section "s_kprobe_f_1" !dbg !65 {
entry:
  %"@_val" = alloca i32, align 4
  %"@_key" = alloca i64, align 8
  %runtime_error_t4 = alloca %runtime_error_t, align 8
  %runtime_error_t = alloca %runtime_error_t, align 8
  %lookup_elem_val = alloca [2 x [2 x [4 x i8]]], align 1
  %"@bar_key1" = alloca i8, align 1
  %"@bar_val" = alloca [2 x [2 x [4 x i8]]], align 1
  %"@bar_key" = alloca i8, align 1
  %1 = call ptr @llvm.preserve.static.offset(ptr %0)
  %2 = getelementptr i8, ptr %1, i64 112
  %arg0 = load volatile i64, ptr %2, align 8
  %3 = inttoptr i64 %arg0 to ptr
  %4 = call ptr @llvm.preserve.static.offset(ptr %3)
  %5 = getelementptr i8, ptr %4, i64 0
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@bar_key")
  store i8 42, ptr %"@bar_key", align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@bar_val")
  %probe_read_kernel = call i64 inttoptr (i64 113 to ptr)(ptr %"@bar_val", i32 16, ptr %5)
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_bar, ptr %"@bar_key", ptr %"@bar_val", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@bar_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@bar_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@bar_key1")
  store i8 42, ptr %"@bar_key1", align 1
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
  %9 = getelementptr [2 x [2 x [4 x i8]]], ptr %lookup_elem_val, i32 0, i8 0
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
  %17 = getelementptr [2 x [4 x i8]], ptr %9, i32 0, i8 1
  %18 = getelementptr [4 x i8], ptr %17, i32 0, i64 0
  %19 = load volatile i32, ptr %18, align 4
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_elem_val)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@_key")
  store i64 0, ptr %"@_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@_val")
  store i32 %19, ptr %"@_val", align 4
  %update_elem11 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_, ptr %"@_key", ptr %"@_val", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@_key")
  ret i64 0

event_loss_counter6:                              ; preds = %is_oob2
  %get_cpu_id9 = call i64 inttoptr (i64 8 to ptr)() #5
  %20 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded10 = and i64 %get_cpu_id9, %20
  %21 = getelementptr [1 x [1 x i64]], ptr @__bt__event_loss_counter, i64 0, i64 %cpu.id.bounded10, i64 0
  %22 = load i64, ptr %21, align 8
  %23 = add i64 %22, 1
  store i64 %23, ptr %21, align 8
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

!llvm.dbg.cu = !{!61}
!llvm.module.flags = !{!63, !64}

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
!21 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !22, size: 64, offset: 192)
!22 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !23, size: 64)
!23 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!24 = !DIGlobalVariableExpression(var: !25, expr: !DIExpression())
!25 = distinct !DIGlobalVariable(name: "AT_bar", linkageName: "global", scope: !2, file: !2, type: !26, isLocal: false, isDefinition: true)
!26 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !27)
!27 = !{!11, !28, !33, !35}
!28 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !29, size: 64, offset: 64)
!29 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !30, size: 64)
!30 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 131072, elements: !31)
!31 = !{!32}
!32 = !DISubrange(count: 4096, lowerBound: 0)
!33 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !34, size: 64, offset: 128)
!34 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!35 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !36, size: 64, offset: 192)
!36 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !37, size: 64)
!37 = !DICompositeType(tag: DW_TAG_array_type, baseType: !38, size: 128, elements: !39)
!38 = !DICompositeType(tag: DW_TAG_array_type, baseType: !3, size: 64, elements: !39)
!39 = !{!40}
!40 = !DISubrange(count: 2, lowerBound: 0)
!41 = !DIGlobalVariableExpression(var: !42, expr: !DIExpression())
!42 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !43, isLocal: false, isDefinition: true)
!43 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !44)
!44 = !{!45, !50}
!45 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !46, size: 64)
!46 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !47, size: 64)
!47 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 864, elements: !48)
!48 = !{!49}
!49 = !DISubrange(count: 27, lowerBound: 0)
!50 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !51, size: 64, offset: 64)
!51 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !52, size: 64)
!52 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 8388608, elements: !53)
!53 = !{!54}
!54 = !DISubrange(count: 262144, lowerBound: 0)
!55 = !DIGlobalVariableExpression(var: !56, expr: !DIExpression())
!56 = distinct !DIGlobalVariable(name: "__bt__event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !57, isLocal: false, isDefinition: true)
!57 = !DICompositeType(tag: DW_TAG_array_type, baseType: !58, size: 64, elements: !15)
!58 = !DICompositeType(tag: DW_TAG_array_type, baseType: !20, size: 64, elements: !15)
!59 = !DIGlobalVariableExpression(var: !60, expr: !DIExpression())
!60 = distinct !DIGlobalVariable(name: "__bt__max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !20, isLocal: false, isDefinition: true)
!61 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !62)
!62 = !{!0, !7, !24, !41, !55, !59}
!63 = !{i32 2, !"Debug Info Version", i32 3}
!64 = !{i32 7, !"uwtable", i32 0}
!65 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !66, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !61, retainedNodes: !68)
!66 = !DISubroutineType(types: !67)
!67 = !{!20, !34}
!68 = !{!69}
!69 = !DILocalVariable(name: "ctx", arg: 1, scope: !65, file: !2, type: !34)
