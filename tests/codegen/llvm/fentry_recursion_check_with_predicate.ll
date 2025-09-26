; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%"struct map_internal_repr_t" = type { ptr, ptr, ptr, ptr }
%"struct map_internal_repr_t.0" = type { ptr, ptr }

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@recursion_prevention = dso_local global %"struct map_internal_repr_t" zeroinitializer, section ".maps", !dbg !7
@ringbuf = dso_local global %"struct map_internal_repr_t.0" zeroinitializer, section ".maps", !dbg !28
@__bt__event_loss_counter = dso_local externally_initialized global [1 x [1 x i64]] zeroinitializer, section ".data.event_loss_counter", !dbg !42
@__bt__max_cpu_id = dso_local externally_initialized constant i64 0, section ".rodata", !dbg !46

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

; Function Attrs: nounwind
define i64 @fentry_mock_vmlinux_queued_spin_lock_slowpath_1(ptr %0) #0 section "s_fentry_mock_vmlinux_queued_spin_lock_slowpath_1" !dbg !52 {
entry:
  %lookup_key8 = alloca i32, align 4
  %lookup_key1 = alloca i32, align 4
  %lookup_key = alloca i32, align 4
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_key)
  store i32 0, ptr %lookup_key, align 4
  %lookup_elem = call ptr inttoptr (i64 1 to ptr)(ptr @recursion_prevention, ptr %lookup_key)
  %map_lookup_cond = icmp ne ptr %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_key)
  %cast = ptrtoint ptr %lookup_elem to i64
  %1 = atomicrmw xchg i64 %cast, i64 1 seq_cst, align 8
  %value_set_condition = icmp eq i64 %1, 0
  br i1 %value_set_condition, label %lookup_merge, label %value_is_set

lookup_failure:                                   ; preds = %entry
  ret i64 0

lookup_merge:                                     ; preds = %lookup_success
  %get_pid_tgid = call i64 inttoptr (i64 14 to ptr)() #2
  %2 = lshr i64 %get_pid_tgid, 32
  %pid = trunc i64 %2 to i32
  %3 = zext i32 %pid to i64
  %4 = icmp eq i64 %3, 1234
  %true_cond = icmp ne i1 %4, false
  br i1 %true_cond, label %left, label %right

value_is_set:                                     ; preds = %lookup_success
  %get_cpu_id = call i64 inttoptr (i64 8 to ptr)() #2
  %5 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded = and i64 %get_cpu_id, %5
  %6 = getelementptr [1 x [1 x i64]], ptr @__bt__event_loss_counter, i64 0, i64 %cpu.id.bounded, i64 0
  %7 = load i64, ptr %6, align 8
  %8 = add i64 %7, 1
  store i64 %8, ptr %6, align 8
  ret i64 0

left:                                             ; preds = %lookup_merge
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_key1)
  store i32 0, ptr %lookup_key1, align 4
  %lookup_elem2 = call ptr inttoptr (i64 1 to ptr)(ptr @recursion_prevention, ptr %lookup_key1)
  %map_lookup_cond6 = icmp ne ptr %lookup_elem2, null
  br i1 %map_lookup_cond6, label %lookup_success3, label %lookup_failure4

right:                                            ; preds = %lookup_merge
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_key8)
  store i32 0, ptr %lookup_key8, align 4
  %lookup_elem9 = call ptr inttoptr (i64 1 to ptr)(ptr @recursion_prevention, ptr %lookup_key8)
  %map_lookup_cond13 = icmp ne ptr %lookup_elem9, null
  br i1 %map_lookup_cond13, label %lookup_success10, label %lookup_failure11

lookup_success3:                                  ; preds = %left
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_key1)
  %cast7 = ptrtoint ptr %lookup_elem2 to i64
  store i64 0, i64 %cast7, align 8
  br label %lookup_merge5

lookup_failure4:                                  ; preds = %left
  br label %lookup_merge5

lookup_merge5:                                    ; preds = %lookup_failure4, %lookup_success3
  ret i64 0

lookup_success10:                                 ; preds = %right
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_key8)
  %cast14 = ptrtoint ptr %lookup_elem9 to i64
  store i64 0, i64 %cast14, align 8
  br label %lookup_merge12

lookup_failure11:                                 ; preds = %right
  br label %lookup_merge12

lookup_merge12:                                   ; preds = %lookup_failure11, %lookup_success10
  ret i64 0
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #2 = { memory(none) }

!llvm.dbg.cu = !{!48}
!llvm.module.flags = !{!50, !51}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "LICENSE", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 32, elements: !5)
!4 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!5 = !{!6}
!6 = !DISubrange(count: 4, lowerBound: 0)
!7 = !DIGlobalVariableExpression(var: !8, expr: !DIExpression())
!8 = distinct !DIGlobalVariable(name: "recursion_prevention", linkageName: "global", scope: !2, file: !2, type: !9, isLocal: false, isDefinition: true)
!9 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !10)
!10 = !{!11, !17, !22, !25}
!11 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !12, size: 64)
!12 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !13, size: 64)
!13 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 192, elements: !15)
!14 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!15 = !{!16}
!16 = !DISubrange(count: 6, lowerBound: 0)
!17 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !18, size: 64, offset: 64)
!18 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !19, size: 64)
!19 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 32, elements: !20)
!20 = !{!21}
!21 = !DISubrange(count: 1, lowerBound: 0)
!22 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !23, size: 64, offset: 128)
!23 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !24, size: 64)
!24 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!25 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !26, size: 64, offset: 192)
!26 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !27, size: 64)
!27 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!28 = !DIGlobalVariableExpression(var: !29, expr: !DIExpression())
!29 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !30, isLocal: false, isDefinition: true)
!30 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !31)
!31 = !{!32, !37}
!32 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !33, size: 64)
!33 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !34, size: 64)
!34 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 864, elements: !35)
!35 = !{!36}
!36 = !DISubrange(count: 27, lowerBound: 0)
!37 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !38, size: 64, offset: 64)
!38 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !39, size: 64)
!39 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 8388608, elements: !40)
!40 = !{!41}
!41 = !DISubrange(count: 262144, lowerBound: 0)
!42 = !DIGlobalVariableExpression(var: !43, expr: !DIExpression())
!43 = distinct !DIGlobalVariable(name: "__bt__event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !44, isLocal: false, isDefinition: true)
!44 = !DICompositeType(tag: DW_TAG_array_type, baseType: !45, size: 64, elements: !20)
!45 = !DICompositeType(tag: DW_TAG_array_type, baseType: !27, size: 64, elements: !20)
!46 = !DIGlobalVariableExpression(var: !47, expr: !DIExpression())
!47 = distinct !DIGlobalVariable(name: "__bt__max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !27, isLocal: false, isDefinition: true)
!48 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !49)
!49 = !{!0, !7, !28, !42, !46}
!50 = !{i32 2, !"Debug Info Version", i32 3}
!51 = !{i32 7, !"uwtable", i32 0}
!52 = distinct !DISubprogram(name: "fentry_mock_vmlinux_queued_spin_lock_slowpath_1", linkageName: "fentry_mock_vmlinux_queued_spin_lock_slowpath_1", scope: !2, file: !2, type: !53, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !48, retainedNodes: !56)
!53 = !DISubroutineType(types: !54)
!54 = !{!27, !55}
!55 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!56 = !{!57}
!57 = !DILocalVariable(name: "ctx", arg: 1, scope: !52, file: !2, type: !55)
