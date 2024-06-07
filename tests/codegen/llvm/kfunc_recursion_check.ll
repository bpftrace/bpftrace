; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { i8*, i8*, i8*, i8* }
%"struct map_t.0" = type { i8*, i8* }
%"struct map_t.1" = type { i8*, i8*, i8*, i8* }
%print_integer_8_t = type <{ i64, i64, [8 x i8] }>

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@recursion_prevention = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@ringbuf = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !22
@event_loss_counter = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !36

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kfunc_queued_spin_lock_slowpath_1(i8* %0) section "s_kfunc_queued_spin_lock_slowpath_1" !dbg !49 {
entry:
  %lookup_key12 = alloca i32, align 4
  %key6 = alloca i32, align 4
  %print_integer_8_t = alloca %print_integer_8_t, align 8
  %key = alloca i32, align 4
  %lookup_key = alloca i32, align 4
  %1 = bitcast i32* %lookup_key to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i32 0, i32* %lookup_key, align 4
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (%"struct map_t"*, i32*)*)(%"struct map_t"* @recursion_prevention, i32* %lookup_key)
  %map_lookup_cond = icmp ne i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  %2 = bitcast i32* %lookup_key to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %2)
  %cast = ptrtoint i8* %lookup_elem to i64
  %3 = atomicrmw xchg i64 %cast, 1 seq_cst
  %value_set_condition = icmp eq i64 %3, 0
  br i1 %value_set_condition, label %lookup_merge, label %value_is_set

lookup_failure:                                   ; preds = %entry
  ret i64 0

lookup_merge:                                     ; preds = %lookup_success
  %4 = bitcast %print_integer_8_t* %print_integer_8_t to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %4)
  %5 = getelementptr %print_integer_8_t, %print_integer_8_t* %print_integer_8_t, i64 0, i32 0
  store i64 30007, i64* %5, align 8
  %6 = getelementptr %print_integer_8_t, %print_integer_8_t* %print_integer_8_t, i64 0, i32 1
  store i64 0, i64* %6, align 8
  %7 = getelementptr %print_integer_8_t, %print_integer_8_t* %print_integer_8_t, i32 0, i32 2
  %8 = bitcast [8 x i8]* %7 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %8, i8 0, i64 8, i1 false)
  %9 = bitcast [8 x i8]* %7 to i64*
  store i64 2, i64* %9, align 8
  %ringbuf_output = call i64 inttoptr (i64 130 to i64 (%"struct map_t.0"*, %print_integer_8_t*, i64, i64)*)(%"struct map_t.0"* @ringbuf, %print_integer_8_t* %print_integer_8_t, i64 24, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

value_is_set:                                     ; preds = %lookup_success
  %10 = bitcast i32* %key to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %10)
  store i32 0, i32* %key, align 4
  %lookup_elem1 = call i8* inttoptr (i64 1 to i8* (%"struct map_t.1"*, i32*)*)(%"struct map_t.1"* @event_loss_counter, i32* %key)
  %map_lookup_cond5 = icmp ne i8* %lookup_elem1, null
  br i1 %map_lookup_cond5, label %lookup_success2, label %lookup_failure3

lookup_success2:                                  ; preds = %value_is_set
  %11 = bitcast i8* %lookup_elem1 to i64*
  %12 = atomicrmw add i64* %11, i64 1 seq_cst
  br label %lookup_merge4

lookup_failure3:                                  ; preds = %value_is_set
  br label %lookup_merge4

lookup_merge4:                                    ; preds = %lookup_failure3, %lookup_success2
  %13 = bitcast i32* %key to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %13)
  ret i64 0

event_loss_counter:                               ; preds = %lookup_merge
  %14 = bitcast i32* %key6 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %14)
  store i32 0, i32* %key6, align 4
  %lookup_elem7 = call i8* inttoptr (i64 1 to i8* (%"struct map_t.1"*, i32*)*)(%"struct map_t.1"* @event_loss_counter, i32* %key6)
  %map_lookup_cond11 = icmp ne i8* %lookup_elem7, null
  br i1 %map_lookup_cond11, label %lookup_success8, label %lookup_failure9

counter_merge:                                    ; preds = %lookup_merge10, %lookup_merge
  %15 = bitcast %print_integer_8_t* %print_integer_8_t to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %15)
  %16 = bitcast i32* %lookup_key12 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %16)
  store i32 0, i32* %lookup_key12, align 4
  %lookup_elem13 = call i8* inttoptr (i64 1 to i8* (%"struct map_t"*, i32*)*)(%"struct map_t"* @recursion_prevention, i32* %lookup_key12)
  %map_lookup_cond17 = icmp ne i8* %lookup_elem13, null
  br i1 %map_lookup_cond17, label %lookup_success14, label %lookup_failure15

lookup_success8:                                  ; preds = %event_loss_counter
  %17 = bitcast i8* %lookup_elem7 to i64*
  %18 = atomicrmw add i64* %17, i64 1 seq_cst
  br label %lookup_merge10

lookup_failure9:                                  ; preds = %event_loss_counter
  br label %lookup_merge10

lookup_merge10:                                   ; preds = %lookup_failure9, %lookup_success8
  %19 = bitcast i32* %key6 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %19)
  br label %counter_merge

lookup_success14:                                 ; preds = %counter_merge
  %20 = bitcast i32* %lookup_key12 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %20)
  %cast18 = ptrtoint i8* %lookup_elem13 to i64
  store i64 0, i64 %cast18, align 8
  br label %lookup_merge16

lookup_failure15:                                 ; preds = %counter_merge
  br label %lookup_merge16

lookup_merge16:                                   ; preds = %lookup_failure15, %lookup_success14
  ret i64 0
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn writeonly
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

define i64 @tracepoint_exceptions_page_fault_user_2(i8* %0) section "s_tracepoint_exceptions_page_fault_user_2" !dbg !56 {
entry:
  %lookup_key12 = alloca i32, align 4
  %key6 = alloca i32, align 4
  %print_integer_8_t = alloca %print_integer_8_t, align 8
  %key = alloca i32, align 4
  %lookup_key = alloca i32, align 4
  %1 = bitcast i32* %lookup_key to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %1)
  store i32 0, i32* %lookup_key, align 4
  %lookup_elem = call i8* inttoptr (i64 1 to i8* (%"struct map_t"*, i32*)*)(%"struct map_t"* @recursion_prevention, i32* %lookup_key)
  %map_lookup_cond = icmp ne i8* %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  %2 = bitcast i32* %lookup_key to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %2)
  %cast = ptrtoint i8* %lookup_elem to i64
  %3 = atomicrmw xchg i64 %cast, 1 seq_cst
  %value_set_condition = icmp eq i64 %3, 0
  br i1 %value_set_condition, label %lookup_merge, label %value_is_set

lookup_failure:                                   ; preds = %entry
  ret i64 0

lookup_merge:                                     ; preds = %lookup_success
  %4 = bitcast %print_integer_8_t* %print_integer_8_t to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %4)
  %5 = getelementptr %print_integer_8_t, %print_integer_8_t* %print_integer_8_t, i64 0, i32 0
  store i64 30007, i64* %5, align 8
  %6 = getelementptr %print_integer_8_t, %print_integer_8_t* %print_integer_8_t, i64 0, i32 1
  store i64 1, i64* %6, align 8
  %7 = getelementptr %print_integer_8_t, %print_integer_8_t* %print_integer_8_t, i32 0, i32 2
  %8 = bitcast [8 x i8]* %7 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %8, i8 0, i64 8, i1 false)
  %9 = bitcast [8 x i8]* %7 to i64*
  store i64 1, i64* %9, align 8
  %ringbuf_output = call i64 inttoptr (i64 130 to i64 (%"struct map_t.0"*, %print_integer_8_t*, i64, i64)*)(%"struct map_t.0"* @ringbuf, %print_integer_8_t* %print_integer_8_t, i64 24, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

value_is_set:                                     ; preds = %lookup_success
  %10 = bitcast i32* %key to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %10)
  store i32 0, i32* %key, align 4
  %lookup_elem1 = call i8* inttoptr (i64 1 to i8* (%"struct map_t.1"*, i32*)*)(%"struct map_t.1"* @event_loss_counter, i32* %key)
  %map_lookup_cond5 = icmp ne i8* %lookup_elem1, null
  br i1 %map_lookup_cond5, label %lookup_success2, label %lookup_failure3

lookup_success2:                                  ; preds = %value_is_set
  %11 = bitcast i8* %lookup_elem1 to i64*
  %12 = atomicrmw add i64* %11, i64 1 seq_cst
  br label %lookup_merge4

lookup_failure3:                                  ; preds = %value_is_set
  br label %lookup_merge4

lookup_merge4:                                    ; preds = %lookup_failure3, %lookup_success2
  %13 = bitcast i32* %key to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %13)
  ret i64 1

event_loss_counter:                               ; preds = %lookup_merge
  %14 = bitcast i32* %key6 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %14)
  store i32 0, i32* %key6, align 4
  %lookup_elem7 = call i8* inttoptr (i64 1 to i8* (%"struct map_t.1"*, i32*)*)(%"struct map_t.1"* @event_loss_counter, i32* %key6)
  %map_lookup_cond11 = icmp ne i8* %lookup_elem7, null
  br i1 %map_lookup_cond11, label %lookup_success8, label %lookup_failure9

counter_merge:                                    ; preds = %lookup_merge10, %lookup_merge
  %15 = bitcast %print_integer_8_t* %print_integer_8_t to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %15)
  %16 = bitcast i32* %lookup_key12 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %16)
  store i32 0, i32* %lookup_key12, align 4
  %lookup_elem13 = call i8* inttoptr (i64 1 to i8* (%"struct map_t"*, i32*)*)(%"struct map_t"* @recursion_prevention, i32* %lookup_key12)
  %map_lookup_cond17 = icmp ne i8* %lookup_elem13, null
  br i1 %map_lookup_cond17, label %lookup_success14, label %lookup_failure15

lookup_success8:                                  ; preds = %event_loss_counter
  %17 = bitcast i8* %lookup_elem7 to i64*
  %18 = atomicrmw add i64* %17, i64 1 seq_cst
  br label %lookup_merge10

lookup_failure9:                                  ; preds = %event_loss_counter
  br label %lookup_merge10

lookup_merge10:                                   ; preds = %lookup_failure9, %lookup_success8
  %19 = bitcast i32* %key6 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %19)
  br label %counter_merge

lookup_success14:                                 ; preds = %counter_merge
  %20 = bitcast i32* %lookup_key12 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %20)
  %cast18 = ptrtoint i8* %lookup_elem13 to i64
  store i64 0, i64 %cast18, align 8
  br label %lookup_merge16

lookup_failure15:                                 ; preds = %counter_merge
  br label %lookup_merge16

lookup_merge16:                                   ; preds = %lookup_failure15, %lookup_success14
  ret i64 1
}

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }
attributes #2 = { argmemonly nofree nosync nounwind willreturn writeonly }

!llvm.dbg.cu = !{!45}
!llvm.module.flags = !{!48}

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
!45 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, enums: !46, globals: !47)
!46 = !{}
!47 = !{!0, !22, !36}
!48 = !{i32 2, !"Debug Info Version", i32 3}
!49 = distinct !DISubprogram(name: "kfunc_queued_spin_lock_slowpath_1", linkageName: "kfunc_queued_spin_lock_slowpath_1", scope: !2, file: !2, type: !50, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !45, retainedNodes: !54)
!50 = !DISubroutineType(types: !51)
!51 = !{!21, !52}
!52 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !53, size: 64)
!53 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!54 = !{!55}
!55 = !DILocalVariable(name: "ctx", arg: 1, scope: !49, file: !2, type: !52)
!56 = distinct !DISubprogram(name: "tracepoint_exceptions_page_fault_user_2", linkageName: "tracepoint_exceptions_page_fault_user_2", scope: !2, file: !2, type: !50, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !45, retainedNodes: !57)
!57 = !{!58}
!58 = !DILocalVariable(name: "ctx", arg: 1, scope: !56, file: !2, type: !52)
