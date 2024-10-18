; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr }
%"struct map_t.1" = type { ptr, ptr, ptr, ptr }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@recursion_prevention = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@ringbuf = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !22
@event_loss_counter = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !36

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @fentry_mock_vmlinux_queued_spin_lock_slowpath_1(ptr %0) section "s_fentry_mock_vmlinux_queued_spin_lock_slowpath_1" !dbg !48 {
entry:
  %lookup_key6 = alloca i32, align 4
  %key = alloca i32, align 4
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
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_key6)
  store i32 0, ptr %lookup_key6, align 4
  %lookup_elem7 = call ptr inttoptr (i64 1 to ptr)(ptr @recursion_prevention, ptr %lookup_key6)
  %map_lookup_cond11 = icmp ne ptr %lookup_elem7, null
  br i1 %map_lookup_cond11, label %lookup_success8, label %lookup_failure9

value_is_set:                                     ; preds = %lookup_success
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key)
  store i32 0, ptr %key, align 4
  %lookup_elem1 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key)
  %map_lookup_cond5 = icmp ne ptr %lookup_elem1, null
  br i1 %map_lookup_cond5, label %lookup_success2, label %lookup_failure3

lookup_success2:                                  ; preds = %value_is_set
  %2 = atomicrmw add ptr %lookup_elem1, i64 1 seq_cst, align 8
  br label %lookup_merge4

lookup_failure3:                                  ; preds = %value_is_set
  br label %lookup_merge4

lookup_merge4:                                    ; preds = %lookup_failure3, %lookup_success2
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key)
  ret i64 0

lookup_success8:                                  ; preds = %lookup_merge
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_key6)
  %cast12 = ptrtoint ptr %lookup_elem7 to i64
  store i64 0, i64 %cast12, align 8
  br label %lookup_merge10

lookup_failure9:                                  ; preds = %lookup_merge
  br label %lookup_merge10

lookup_merge10:                                   ; preds = %lookup_failure9, %lookup_success8
  ret i64 0
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

define i64 @tracepoint_exceptions_page_fault_user_2(ptr %0) section "s_tracepoint_exceptions_page_fault_user_2" !dbg !55 {
entry:
  %lookup_key6 = alloca i32, align 4
  %key = alloca i32, align 4
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
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_key6)
  store i32 0, ptr %lookup_key6, align 4
  %lookup_elem7 = call ptr inttoptr (i64 1 to ptr)(ptr @recursion_prevention, ptr %lookup_key6)
  %map_lookup_cond11 = icmp ne ptr %lookup_elem7, null
  br i1 %map_lookup_cond11, label %lookup_success8, label %lookup_failure9

value_is_set:                                     ; preds = %lookup_success
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key)
  store i32 0, ptr %key, align 4
  %lookup_elem1 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key)
  %map_lookup_cond5 = icmp ne ptr %lookup_elem1, null
  br i1 %map_lookup_cond5, label %lookup_success2, label %lookup_failure3

lookup_success2:                                  ; preds = %value_is_set
  %2 = atomicrmw add ptr %lookup_elem1, i64 1 seq_cst, align 8
  br label %lookup_merge4

lookup_failure3:                                  ; preds = %value_is_set
  br label %lookup_merge4

lookup_merge4:                                    ; preds = %lookup_failure3, %lookup_success2
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key)
  ret i64 1

lookup_success8:                                  ; preds = %lookup_merge
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_key6)
  %cast12 = ptrtoint ptr %lookup_elem7 to i64
  store i64 0, i64 %cast12, align 8
  br label %lookup_merge10

lookup_failure9:                                  ; preds = %lookup_merge
  br label %lookup_merge10

lookup_merge10:                                   ; preds = %lookup_failure9, %lookup_success8
  ret i64 1
}

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }

!llvm.dbg.cu = !{!45}
!llvm.module.flags = !{!47}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "recursion_prevention", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !4)
!4 = !{!5, !11, !16, !19}
!5 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !6, size: 64)
!6 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !7, size: 64)
!7 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 192, elements: !9)
!8 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!9 = !{!10}
!10 = !DISubrange(count: 6, lowerBound: 0)
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
!23 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !24, isLocal: false, isDefinition: true)
!24 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !25)
!25 = !{!26, !31}
!26 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !27, size: 64)
!27 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !28, size: 64)
!28 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !29)
!29 = !{!30}
!30 = !DISubrange(count: 27, lowerBound: 0)
!31 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !32, size: 64, offset: 64)
!32 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !33, size: 64)
!33 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !34)
!34 = !{!35}
!35 = !DISubrange(count: 262144, lowerBound: 0)
!36 = !DIGlobalVariableExpression(var: !37, expr: !DIExpression())
!37 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !38, isLocal: false, isDefinition: true)
!38 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !39)
!39 = !{!40, !11, !16, !19}
!40 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !41, size: 64)
!41 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !42, size: 64)
!42 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !43)
!43 = !{!44}
!44 = !DISubrange(count: 2, lowerBound: 0)
!45 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !46)
!46 = !{!0, !22, !36}
!47 = !{i32 2, !"Debug Info Version", i32 3}
!48 = distinct !DISubprogram(name: "fentry_mock_vmlinux_queued_spin_lock_slowpath_1", linkageName: "fentry_mock_vmlinux_queued_spin_lock_slowpath_1", scope: !2, file: !2, type: !49, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !45, retainedNodes: !53)
!49 = !DISubroutineType(types: !50)
!50 = !{!21, !51}
!51 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !52, size: 64)
!52 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!53 = !{!54}
!54 = !DILocalVariable(name: "ctx", arg: 1, scope: !48, file: !2, type: !51)
!55 = distinct !DISubprogram(name: "tracepoint_exceptions_page_fault_user_2", linkageName: "tracepoint_exceptions_page_fault_user_2", scope: !2, file: !2, type: !49, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !45, retainedNodes: !56)
!56 = !{!57}
!57 = !DILocalVariable(name: "ctx", arg: 1, scope: !55, file: !2, type: !51)
