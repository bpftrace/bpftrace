; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%"struct map_internal_repr_t" = type { ptr, ptr, ptr, ptr }
%"struct map_internal_repr_t.0" = type { ptr, ptr, ptr, ptr }
%"struct map_internal_repr_t.1" = type { ptr, ptr }
%runtime_error_t = type <{ i64, i64, i32 }>

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@AT_x = dso_local global %"struct map_internal_repr_t" zeroinitializer, section ".maps", !dbg !7
@AT_y = dso_local global %"struct map_internal_repr_t.0" zeroinitializer, section ".maps", !dbg !22
@ringbuf = dso_local global %"struct map_internal_repr_t.1" zeroinitializer, section ".maps", !dbg !24
@__bt__event_loss_counter = dso_local externally_initialized global [1 x [1 x i64]] zeroinitializer, section ".data.event_loss_counter", !dbg !38
@__bt__max_cpu_id = dso_local externally_initialized constant i64 0, section ".rodata", !dbg !42

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

; Function Attrs: nounwind
define i64 @kprobe_f_1(ptr %0) #0 section "s_kprobe_f_1" !dbg !48 {
entry:
  %runtime_error_t5 = alloca %runtime_error_t, align 8
  %"@y_val" = alloca i64, align 8
  %"@y_key" = alloca i64, align 8
  %runtime_error_t = alloca %runtime_error_t, align 8
  %"@x_val" = alloca i64, align 8
  %"@x_key" = alloca i64, align 8
  %get_pid_tgid = call i64 inttoptr (i64 14 to ptr)() #2
  %1 = lshr i64 %get_pid_tgid, 32
  %pid = trunc i64 %1 to i32
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key")
  store i64 0, ptr %"@x_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_val")
  %2 = zext i32 %pid to i64
  store i64 %2, ptr %"@x_val", align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %"@x_key", ptr %"@x_val", i64 0)
  %3 = trunc i64 %update_elem to i32
  %4 = icmp sge i32 %3, 0
  br i1 %4, label %helper_merge, label %helper_failure

helper_failure:                                   ; preds = %entry
  call void @llvm.lifetime.start.p0(i64 -1, ptr %runtime_error_t)
  %5 = getelementptr %runtime_error_t, ptr %runtime_error_t, i64 0, i32 0
  store i64 30006, ptr %5, align 8
  %6 = getelementptr %runtime_error_t, ptr %runtime_error_t, i64 0, i32 1
  store i64 0, ptr %6, align 8
  %7 = getelementptr %runtime_error_t, ptr %runtime_error_t, i64 0, i32 2
  store i32 %3, ptr %7, align 4
  %ringbuf_output = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %runtime_error_t, i64 20, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

helper_merge:                                     ; preds = %counter_merge, %entry
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_val")
  %get_pid_tgid1 = call i64 inttoptr (i64 14 to ptr)() #2
  %tid = trunc i64 %get_pid_tgid1 to i32
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@y_key")
  store i64 0, ptr %"@y_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@y_val")
  %8 = zext i32 %tid to i64
  store i64 %8, ptr %"@y_val", align 8
  %update_elem2 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_y, ptr %"@y_key", ptr %"@y_val", i64 0)
  %9 = trunc i64 %update_elem2 to i32
  %10 = icmp sge i32 %9, 0
  br i1 %10, label %helper_merge4, label %helper_failure3

event_loss_counter:                               ; preds = %helper_failure
  %get_cpu_id = call i64 inttoptr (i64 8 to ptr)() #2
  %11 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded = and i64 %get_cpu_id, %11
  %12 = getelementptr [1 x [1 x i64]], ptr @__bt__event_loss_counter, i64 0, i64 %cpu.id.bounded, i64 0
  %13 = load i64, ptr %12, align 8
  %14 = add i64 %13, 1
  store i64 %14, ptr %12, align 8
  br label %counter_merge

counter_merge:                                    ; preds = %event_loss_counter, %helper_failure
  call void @llvm.lifetime.end.p0(i64 -1, ptr %runtime_error_t)
  br label %helper_merge

helper_failure3:                                  ; preds = %helper_merge
  call void @llvm.lifetime.start.p0(i64 -1, ptr %runtime_error_t5)
  %15 = getelementptr %runtime_error_t, ptr %runtime_error_t5, i64 0, i32 0
  store i64 30006, ptr %15, align 8
  %16 = getelementptr %runtime_error_t, ptr %runtime_error_t5, i64 0, i32 1
  store i64 1, ptr %16, align 8
  %17 = getelementptr %runtime_error_t, ptr %runtime_error_t5, i64 0, i32 2
  store i32 %9, ptr %17, align 4
  %ringbuf_output6 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %runtime_error_t5, i64 20, i64 0)
  %ringbuf_loss9 = icmp slt i64 %ringbuf_output6, 0
  br i1 %ringbuf_loss9, label %event_loss_counter7, label %counter_merge8

helper_merge4:                                    ; preds = %counter_merge8, %helper_merge
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@y_key")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@y_val")
  ret i64 0

event_loss_counter7:                              ; preds = %helper_failure3
  %get_cpu_id10 = call i64 inttoptr (i64 8 to ptr)() #2
  %18 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded11 = and i64 %get_cpu_id10, %18
  %19 = getelementptr [1 x [1 x i64]], ptr @__bt__event_loss_counter, i64 0, i64 %cpu.id.bounded11, i64 0
  %20 = load i64, ptr %19, align 8
  %21 = add i64 %20, 1
  store i64 %21, ptr %19, align 8
  br label %counter_merge8

counter_merge8:                                   ; preds = %event_loss_counter7, %helper_failure3
  call void @llvm.lifetime.end.p0(i64 -1, ptr %runtime_error_t5)
  br label %helper_merge4
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #2 = { memory(none) }

!llvm.dbg.cu = !{!44}
!llvm.module.flags = !{!46, !47}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "LICENSE", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 32, elements: !5)
!4 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!5 = !{!6}
!6 = !DISubrange(count: 4, lowerBound: 0)
!7 = !DIGlobalVariableExpression(var: !8, expr: !DIExpression())
!8 = distinct !DIGlobalVariable(name: "AT_x", linkageName: "global", scope: !2, file: !2, type: !9, isLocal: false, isDefinition: true)
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
!23 = distinct !DIGlobalVariable(name: "AT_y", linkageName: "global", scope: !2, file: !2, type: !9, isLocal: false, isDefinition: true)
!24 = !DIGlobalVariableExpression(var: !25, expr: !DIExpression())
!25 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !26, isLocal: false, isDefinition: true)
!26 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !27)
!27 = !{!28, !33}
!28 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !29, size: 64)
!29 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !30, size: 64)
!30 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 864, elements: !31)
!31 = !{!32}
!32 = !DISubrange(count: 27, lowerBound: 0)
!33 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !34, size: 64, offset: 64)
!34 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !35, size: 64)
!35 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 8388608, elements: !36)
!36 = !{!37}
!37 = !DISubrange(count: 262144, lowerBound: 0)
!38 = !DIGlobalVariableExpression(var: !39, expr: !DIExpression())
!39 = distinct !DIGlobalVariable(name: "__bt__event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !40, isLocal: false, isDefinition: true)
!40 = !DICompositeType(tag: DW_TAG_array_type, baseType: !41, size: 64, elements: !15)
!41 = !DICompositeType(tag: DW_TAG_array_type, baseType: !20, size: 64, elements: !15)
!42 = !DIGlobalVariableExpression(var: !43, expr: !DIExpression())
!43 = distinct !DIGlobalVariable(name: "__bt__max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !20, isLocal: false, isDefinition: true)
!44 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !45)
!45 = !{!0, !7, !22, !24, !38, !42}
!46 = !{i32 2, !"Debug Info Version", i32 3}
!47 = !{i32 7, !"uwtable", i32 0}
!48 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !49, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !44, retainedNodes: !52)
!49 = !DISubroutineType(types: !50)
!50 = !{!20, !51}
!51 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!52 = !{!53}
!53 = !DILocalVariable(name: "ctx", arg: 1, scope: !48, file: !2, type: !51)
