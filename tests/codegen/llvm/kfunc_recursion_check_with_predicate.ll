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
  %lookup_key19 = alloca i32, align 4
  %key13 = alloca i32, align 4
  %print_integer_8_t = alloca %print_integer_8_t, align 8
  %lookup_key6 = alloca i32, align 4
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
  %get_pid_tgid = call i64 inttoptr (i64 14 to i64 ()*)()
  %4 = lshr i64 %get_pid_tgid, 32
  %5 = icmp eq i64 %4, 1234
  %6 = zext i1 %5 to i64
  %predcond = icmp eq i64 %6, 0
  br i1 %predcond, label %pred_false, label %pred_true

value_is_set:                                     ; preds = %lookup_success
  %7 = bitcast i32* %key to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %7)
  store i32 0, i32* %key, align 4
  %lookup_elem1 = call i8* inttoptr (i64 1 to i8* (%"struct map_t.1"*, i32*)*)(%"struct map_t.1"* @event_loss_counter, i32* %key)
  %map_lookup_cond5 = icmp ne i8* %lookup_elem1, null
  br i1 %map_lookup_cond5, label %lookup_success2, label %lookup_failure3

lookup_success2:                                  ; preds = %value_is_set
  %8 = bitcast i8* %lookup_elem1 to i64*
  %9 = atomicrmw add i64* %8, i64 1 seq_cst
  br label %lookup_merge4

lookup_failure3:                                  ; preds = %value_is_set
  br label %lookup_merge4

lookup_merge4:                                    ; preds = %lookup_failure3, %lookup_success2
  %10 = bitcast i32* %key to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %10)
  ret i64 0

pred_false:                                       ; preds = %lookup_merge
  %11 = bitcast i32* %lookup_key6 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %11)
  store i32 0, i32* %lookup_key6, align 4
  %lookup_elem7 = call i8* inttoptr (i64 1 to i8* (%"struct map_t"*, i32*)*)(%"struct map_t"* @recursion_prevention, i32* %lookup_key6)
  %map_lookup_cond11 = icmp ne i8* %lookup_elem7, null
  br i1 %map_lookup_cond11, label %lookup_success8, label %lookup_failure9

pred_true:                                        ; preds = %lookup_merge
  %12 = bitcast %print_integer_8_t* %print_integer_8_t to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %12)
  %13 = getelementptr %print_integer_8_t, %print_integer_8_t* %print_integer_8_t, i64 0, i32 0
  store i64 30007, i64* %13, align 8
  %14 = getelementptr %print_integer_8_t, %print_integer_8_t* %print_integer_8_t, i64 0, i32 1
  store i64 0, i64* %14, align 8
  %15 = getelementptr %print_integer_8_t, %print_integer_8_t* %print_integer_8_t, i32 0, i32 2
  %16 = bitcast [8 x i8]* %15 to i8*
  call void @llvm.memset.p0i8.i64(i8* align 1 %16, i8 0, i64 8, i1 false)
  %17 = bitcast [8 x i8]* %15 to i64*
  store i64 2, i64* %17, align 8
  %ringbuf_output = call i64 inttoptr (i64 130 to i64 (%"struct map_t.0"*, %print_integer_8_t*, i64, i64)*)(%"struct map_t.0"* @ringbuf, %print_integer_8_t* %print_integer_8_t, i64 24, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

lookup_success8:                                  ; preds = %pred_false
  %18 = bitcast i32* %lookup_key6 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %18)
  %cast12 = ptrtoint i8* %lookup_elem7 to i64
  store i64 0, i64 %cast12, align 8
  br label %lookup_merge10

lookup_failure9:                                  ; preds = %pred_false
  br label %lookup_merge10

lookup_merge10:                                   ; preds = %lookup_failure9, %lookup_success8
  ret i64 0

event_loss_counter:                               ; preds = %pred_true
  %19 = bitcast i32* %key13 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %19)
  store i32 0, i32* %key13, align 4
  %lookup_elem14 = call i8* inttoptr (i64 1 to i8* (%"struct map_t.1"*, i32*)*)(%"struct map_t.1"* @event_loss_counter, i32* %key13)
  %map_lookup_cond18 = icmp ne i8* %lookup_elem14, null
  br i1 %map_lookup_cond18, label %lookup_success15, label %lookup_failure16

counter_merge:                                    ; preds = %lookup_merge17, %pred_true
  %20 = bitcast %print_integer_8_t* %print_integer_8_t to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %20)
  %21 = bitcast i32* %lookup_key19 to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* %21)
  store i32 0, i32* %lookup_key19, align 4
  %lookup_elem20 = call i8* inttoptr (i64 1 to i8* (%"struct map_t"*, i32*)*)(%"struct map_t"* @recursion_prevention, i32* %lookup_key19)
  %map_lookup_cond24 = icmp ne i8* %lookup_elem20, null
  br i1 %map_lookup_cond24, label %lookup_success21, label %lookup_failure22

lookup_success15:                                 ; preds = %event_loss_counter
  %22 = bitcast i8* %lookup_elem14 to i64*
  %23 = atomicrmw add i64* %22, i64 1 seq_cst
  br label %lookup_merge17

lookup_failure16:                                 ; preds = %event_loss_counter
  br label %lookup_merge17

lookup_merge17:                                   ; preds = %lookup_failure16, %lookup_success15
  %24 = bitcast i32* %key13 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %24)
  br label %counter_merge

lookup_success21:                                 ; preds = %counter_merge
  %25 = bitcast i32* %lookup_key19 to i8*
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* %25)
  %cast25 = ptrtoint i8* %lookup_elem20 to i64
  store i64 0, i64 %cast25, align 8
  br label %lookup_merge23

lookup_failure22:                                 ; preds = %counter_merge
  br label %lookup_merge23

lookup_merge23:                                   ; preds = %lookup_failure22, %lookup_success21
  ret i64 0
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn writeonly
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

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
