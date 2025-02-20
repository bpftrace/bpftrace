; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr, ptr, ptr }
%"struct map_t.1" = type { ptr, ptr }
%"struct map_t.2" = type { ptr, ptr, ptr, ptr }
%helper_error_t = type <{ i64, i64, i32 }>
%bpf_pidns_info = type { i32, i32 }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_x = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@AT_y = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !16
@ringbuf = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !18
@event_loss_counter = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !32

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(ptr %0) section "s_kprobe_f_1" !dbg !47 {
entry:
  %key37 = alloca i32, align 4
  %helper_error_t32 = alloca %helper_error_t, align 8
  %"@y_val" = alloca i64, align 8
  %"@y_key" = alloca i64, align 8
  %key23 = alloca i32, align 4
  %helper_error_t18 = alloca %helper_error_t, align 8
  %bpf_pidns_info14 = alloca %bpf_pidns_info, align 8
  %key8 = alloca i32, align 4
  %helper_error_t3 = alloca %helper_error_t, align 8
  %"@x_val" = alloca i64, align 8
  %"@x_key" = alloca i64, align 8
  %key = alloca i32, align 4
  %helper_error_t = alloca %helper_error_t, align 8
  %bpf_pidns_info = alloca %bpf_pidns_info, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %bpf_pidns_info)
  %get_ns_pid_tgid = call i64 inttoptr (i64 120 to ptr)(i64 0, i64 4026531857, ptr %bpf_pidns_info, i32 8)
  %1 = trunc i64 %get_ns_pid_tgid to i32
  %2 = icmp sge i32 %1, 0
  br i1 %2, label %helper_merge, label %helper_failure

helper_failure:                                   ; preds = %entry
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t)
  %3 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 0
  store i64 30006, ptr %3, align 8
  %4 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 1
  store i64 0, ptr %4, align 8
  %5 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 2
  store i32 %1, ptr %5, align 4
  %ringbuf_output = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t, i64 20, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

helper_merge:                                     ; preds = %counter_merge, %entry
  %6 = getelementptr %bpf_pidns_info, ptr %bpf_pidns_info, i32 0, i32 0
  %7 = load i32, ptr %6, align 4
  call void @llvm.lifetime.end.p0(i64 -1, ptr %bpf_pidns_info)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key")
  store i64 0, ptr %"@x_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_val")
  %8 = zext i32 %7 to i64
  store i64 %8, ptr %"@x_val", align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %"@x_key", ptr %"@x_val", i64 0)
  %9 = trunc i64 %update_elem to i32
  %10 = icmp sge i32 %9, 0
  br i1 %10, label %helper_merge2, label %helper_failure1

event_loss_counter:                               ; preds = %helper_failure
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key)
  store i32 0, ptr %key, align 4
  %lookup_elem = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key)
  %map_lookup_cond = icmp ne ptr %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

counter_merge:                                    ; preds = %lookup_merge, %helper_failure
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t)
  br label %helper_merge

lookup_success:                                   ; preds = %event_loss_counter
  %11 = atomicrmw add ptr %lookup_elem, i64 1 seq_cst, align 8
  br label %lookup_merge

lookup_failure:                                   ; preds = %event_loss_counter
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key)
  br label %counter_merge

helper_failure1:                                  ; preds = %helper_merge
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t3)
  %12 = getelementptr %helper_error_t, ptr %helper_error_t3, i64 0, i32 0
  store i64 30006, ptr %12, align 8
  %13 = getelementptr %helper_error_t, ptr %helper_error_t3, i64 0, i32 1
  store i64 1, ptr %13, align 8
  %14 = getelementptr %helper_error_t, ptr %helper_error_t3, i64 0, i32 2
  store i32 %9, ptr %14, align 4
  %ringbuf_output4 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t3, i64 20, i64 0)
  %ringbuf_loss7 = icmp slt i64 %ringbuf_output4, 0
  br i1 %ringbuf_loss7, label %event_loss_counter5, label %counter_merge6

helper_merge2:                                    ; preds = %counter_merge6, %helper_merge
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %bpf_pidns_info14)
  %get_ns_pid_tgid15 = call i64 inttoptr (i64 120 to ptr)(i64 0, i64 4026531857, ptr %bpf_pidns_info14, i32 8)
  %15 = trunc i64 %get_ns_pid_tgid15 to i32
  %16 = icmp sge i32 %15, 0
  br i1 %16, label %helper_merge17, label %helper_failure16

event_loss_counter5:                              ; preds = %helper_failure1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key8)
  store i32 0, ptr %key8, align 4
  %lookup_elem9 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key8)
  %map_lookup_cond13 = icmp ne ptr %lookup_elem9, null
  br i1 %map_lookup_cond13, label %lookup_success10, label %lookup_failure11

counter_merge6:                                   ; preds = %lookup_merge12, %helper_failure1
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t3)
  br label %helper_merge2

lookup_success10:                                 ; preds = %event_loss_counter5
  %17 = atomicrmw add ptr %lookup_elem9, i64 1 seq_cst, align 8
  br label %lookup_merge12

lookup_failure11:                                 ; preds = %event_loss_counter5
  br label %lookup_merge12

lookup_merge12:                                   ; preds = %lookup_failure11, %lookup_success10
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key8)
  br label %counter_merge6

helper_failure16:                                 ; preds = %helper_merge2
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t18)
  %18 = getelementptr %helper_error_t, ptr %helper_error_t18, i64 0, i32 0
  store i64 30006, ptr %18, align 8
  %19 = getelementptr %helper_error_t, ptr %helper_error_t18, i64 0, i32 1
  store i64 2, ptr %19, align 8
  %20 = getelementptr %helper_error_t, ptr %helper_error_t18, i64 0, i32 2
  store i32 %15, ptr %20, align 4
  %ringbuf_output19 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t18, i64 20, i64 0)
  %ringbuf_loss22 = icmp slt i64 %ringbuf_output19, 0
  br i1 %ringbuf_loss22, label %event_loss_counter20, label %counter_merge21

helper_merge17:                                   ; preds = %counter_merge21, %helper_merge2
  %21 = getelementptr %bpf_pidns_info, ptr %bpf_pidns_info14, i32 0, i32 1
  %22 = load i32, ptr %21, align 4
  call void @llvm.lifetime.end.p0(i64 -1, ptr %bpf_pidns_info14)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@y_key")
  store i64 0, ptr %"@y_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@y_val")
  %23 = zext i32 %22 to i64
  store i64 %23, ptr %"@y_val", align 8
  %update_elem29 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_y, ptr %"@y_key", ptr %"@y_val", i64 0)
  %24 = trunc i64 %update_elem29 to i32
  %25 = icmp sge i32 %24, 0
  br i1 %25, label %helper_merge31, label %helper_failure30

event_loss_counter20:                             ; preds = %helper_failure16
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key23)
  store i32 0, ptr %key23, align 4
  %lookup_elem24 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key23)
  %map_lookup_cond28 = icmp ne ptr %lookup_elem24, null
  br i1 %map_lookup_cond28, label %lookup_success25, label %lookup_failure26

counter_merge21:                                  ; preds = %lookup_merge27, %helper_failure16
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t18)
  br label %helper_merge17

lookup_success25:                                 ; preds = %event_loss_counter20
  %26 = atomicrmw add ptr %lookup_elem24, i64 1 seq_cst, align 8
  br label %lookup_merge27

lookup_failure26:                                 ; preds = %event_loss_counter20
  br label %lookup_merge27

lookup_merge27:                                   ; preds = %lookup_failure26, %lookup_success25
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key23)
  br label %counter_merge21

helper_failure30:                                 ; preds = %helper_merge17
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t32)
  %27 = getelementptr %helper_error_t, ptr %helper_error_t32, i64 0, i32 0
  store i64 30006, ptr %27, align 8
  %28 = getelementptr %helper_error_t, ptr %helper_error_t32, i64 0, i32 1
  store i64 3, ptr %28, align 8
  %29 = getelementptr %helper_error_t, ptr %helper_error_t32, i64 0, i32 2
  store i32 %24, ptr %29, align 4
  %ringbuf_output33 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t32, i64 20, i64 0)
  %ringbuf_loss36 = icmp slt i64 %ringbuf_output33, 0
  br i1 %ringbuf_loss36, label %event_loss_counter34, label %counter_merge35

helper_merge31:                                   ; preds = %counter_merge35, %helper_merge17
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@y_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@y_key")
  ret i64 0

event_loss_counter34:                             ; preds = %helper_failure30
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key37)
  store i32 0, ptr %key37, align 4
  %lookup_elem38 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key37)
  %map_lookup_cond42 = icmp ne ptr %lookup_elem38, null
  br i1 %map_lookup_cond42, label %lookup_success39, label %lookup_failure40

counter_merge35:                                  ; preds = %lookup_merge41, %helper_failure30
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t32)
  br label %helper_merge31

lookup_success39:                                 ; preds = %event_loss_counter34
  %30 = atomicrmw add ptr %lookup_elem38, i64 1 seq_cst, align 8
  br label %lookup_merge41

lookup_failure40:                                 ; preds = %event_loss_counter34
  br label %lookup_merge41

lookup_merge41:                                   ; preds = %lookup_failure40, %lookup_success39
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key37)
  br label %counter_merge35
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }

!llvm.dbg.cu = !{!44}
!llvm.module.flags = !{!46}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "AT_x", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !4)
!4 = !{!5, !11, !12, !15}
!5 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !6, size: 64)
!6 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !7, size: 64)
!7 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 32, elements: !9)
!8 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!9 = !{!10}
!10 = !DISubrange(count: 1, lowerBound: 0)
!11 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !6, size: 64, offset: 64)
!12 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !13, size: 64, offset: 128)
!13 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !14, size: 64)
!14 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!15 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !13, size: 64, offset: 192)
!16 = !DIGlobalVariableExpression(var: !17, expr: !DIExpression())
!17 = distinct !DIGlobalVariable(name: "AT_y", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!18 = !DIGlobalVariableExpression(var: !19, expr: !DIExpression())
!19 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !20, isLocal: false, isDefinition: true)
!20 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !21)
!21 = !{!22, !27}
!22 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !23, size: 64)
!23 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !24, size: 64)
!24 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !25)
!25 = !{!26}
!26 = !DISubrange(count: 27, lowerBound: 0)
!27 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !28, size: 64, offset: 64)
!28 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !29, size: 64)
!29 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !30)
!30 = !{!31}
!31 = !DISubrange(count: 262144, lowerBound: 0)
!32 = !DIGlobalVariableExpression(var: !33, expr: !DIExpression())
!33 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !34, isLocal: false, isDefinition: true)
!34 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !35)
!35 = !{!36, !11, !41, !15}
!36 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !37, size: 64)
!37 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !38, size: 64)
!38 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !39)
!39 = !{!40}
!40 = !DISubrange(count: 2, lowerBound: 0)
!41 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !42, size: 64, offset: 128)
!42 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !43, size: 64)
!43 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!44 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !45)
!45 = !{!0, !16, !18, !32}
!46 = !{i32 2, !"Debug Info Version", i32 3}
!47 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !48, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !44, retainedNodes: !52)
!48 = !DISubroutineType(types: !49)
!49 = !{!14, !50}
!50 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !51, size: 64)
!51 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!52 = !{!53}
!53 = !DILocalVariable(name: "ctx", arg: 1, scope: !47, file: !2, type: !50)
