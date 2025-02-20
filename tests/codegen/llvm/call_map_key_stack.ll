; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr, ptr, ptr }
%"struct map_t.1" = type { ptr, ptr }
%"struct map_t.2" = type { ptr, ptr, ptr, ptr }
%helper_error_t = type <{ i64, i64, i32 }>

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_x = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@AT_y = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !20
@ringbuf = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !22
@event_loss_counter = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !36
@num_cpus = dso_local externally_initialized constant i64 zeroinitializer, section ".rodata", !dbg !53

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(ptr %0) section "s_kprobe_f_1" !dbg !58 {
entry:
  %key37 = alloca i32, align 4
  %helper_error_t32 = alloca %helper_error_t, align 8
  %"@x_key29" = alloca i64, align 8
  %"@x_key27" = alloca i64, align 8
  %key21 = alloca i32, align 4
  %helper_error_t16 = alloca %helper_error_t, align 8
  %initial_value12 = alloca i64, align 8
  %lookup_elem_val10 = alloca i64, align 8
  %"@y_key" = alloca i64, align 8
  %key = alloca i32, align 4
  %helper_error_t = alloca %helper_error_t, align 8
  %initial_value = alloca i64, align 8
  %lookup_elem_val = alloca i64, align 8
  %"@x_key" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key")
  store i64 1, ptr %"@x_key", align 8
  %lookup_elem = call ptr inttoptr (i64 1 to ptr)(ptr @AT_x, ptr %"@x_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_elem_val)
  %map_lookup_cond = icmp ne ptr %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  %1 = load i64, ptr %lookup_elem, align 8
  %2 = add i64 %1, 1
  store i64 %2, ptr %lookup_elem, align 8
  br label %lookup_merge

lookup_failure:                                   ; preds = %entry
  call void @llvm.lifetime.start.p0(i64 -1, ptr %initial_value)
  store i64 1, ptr %initial_value, align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %"@x_key", ptr %initial_value, i64 1)
  %3 = trunc i64 %update_elem to i32
  %4 = icmp sge i32 %3, 0
  br i1 %4, label %helper_merge, label %helper_failure

lookup_merge:                                     ; preds = %helper_merge, %lookup_success
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_elem_val)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key")
  %log2 = call i64 @log2(i64 10, i64 0)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@y_key")
  store i64 %log2, ptr %"@y_key", align 8
  %lookup_elem6 = call ptr inttoptr (i64 1 to ptr)(ptr @AT_y, ptr %"@y_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_elem_val10)
  %map_lookup_cond11 = icmp ne ptr %lookup_elem6, null
  br i1 %map_lookup_cond11, label %lookup_success7, label %lookup_failure8

helper_failure:                                   ; preds = %lookup_failure
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t)
  %5 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 0
  store i64 30006, ptr %5, align 8
  %6 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 1
  store i64 0, ptr %6, align 8
  %7 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 2
  store i32 %3, ptr %7, align 4
  %ringbuf_output = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t, i64 20, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

helper_merge:                                     ; preds = %counter_merge, %lookup_failure
  call void @llvm.lifetime.end.p0(i64 -1, ptr %initial_value)
  br label %lookup_merge

event_loss_counter:                               ; preds = %helper_failure
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key)
  store i32 0, ptr %key, align 4
  %lookup_elem1 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key)
  %map_lookup_cond5 = icmp ne ptr %lookup_elem1, null
  br i1 %map_lookup_cond5, label %lookup_success2, label %lookup_failure3

counter_merge:                                    ; preds = %lookup_merge4, %helper_failure
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t)
  br label %helper_merge

lookup_success2:                                  ; preds = %event_loss_counter
  %8 = atomicrmw add ptr %lookup_elem1, i64 1 seq_cst, align 8
  br label %lookup_merge4

lookup_failure3:                                  ; preds = %event_loss_counter
  br label %lookup_merge4

lookup_merge4:                                    ; preds = %lookup_failure3, %lookup_success2
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key)
  br label %counter_merge

lookup_success7:                                  ; preds = %lookup_merge
  %9 = load i64, ptr %lookup_elem6, align 8
  %10 = add i64 %9, 1
  store i64 %10, ptr %lookup_elem6, align 8
  br label %lookup_merge9

lookup_failure8:                                  ; preds = %lookup_merge
  call void @llvm.lifetime.start.p0(i64 -1, ptr %initial_value12)
  store i64 1, ptr %initial_value12, align 8
  %update_elem13 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_y, ptr %"@y_key", ptr %initial_value12, i64 1)
  %11 = trunc i64 %update_elem13 to i32
  %12 = icmp sge i32 %11, 0
  br i1 %12, label %helper_merge15, label %helper_failure14

lookup_merge9:                                    ; preds = %helper_merge15, %lookup_success7
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_elem_val10)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@y_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key27")
  store i64 1, ptr %"@x_key27", align 8
  %lookup_elem28 = call ptr inttoptr (i64 1 to ptr)(ptr @AT_x, ptr %"@x_key27")
  %has_key = icmp ne ptr %lookup_elem28, null
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key27")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key29")
  store i64 1, ptr %"@x_key29", align 8
  %delete_elem = call i64 inttoptr (i64 3 to ptr)(ptr @AT_x, ptr %"@x_key29")
  %13 = trunc i64 %delete_elem to i32
  %14 = icmp sge i32 %13, 0
  br i1 %14, label %helper_merge31, label %helper_failure30

helper_failure14:                                 ; preds = %lookup_failure8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t16)
  %15 = getelementptr %helper_error_t, ptr %helper_error_t16, i64 0, i32 0
  store i64 30006, ptr %15, align 8
  %16 = getelementptr %helper_error_t, ptr %helper_error_t16, i64 0, i32 1
  store i64 1, ptr %16, align 8
  %17 = getelementptr %helper_error_t, ptr %helper_error_t16, i64 0, i32 2
  store i32 %11, ptr %17, align 4
  %ringbuf_output17 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t16, i64 20, i64 0)
  %ringbuf_loss20 = icmp slt i64 %ringbuf_output17, 0
  br i1 %ringbuf_loss20, label %event_loss_counter18, label %counter_merge19

helper_merge15:                                   ; preds = %counter_merge19, %lookup_failure8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %initial_value12)
  br label %lookup_merge9

event_loss_counter18:                             ; preds = %helper_failure14
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key21)
  store i32 0, ptr %key21, align 4
  %lookup_elem22 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key21)
  %map_lookup_cond26 = icmp ne ptr %lookup_elem22, null
  br i1 %map_lookup_cond26, label %lookup_success23, label %lookup_failure24

counter_merge19:                                  ; preds = %lookup_merge25, %helper_failure14
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t16)
  br label %helper_merge15

lookup_success23:                                 ; preds = %event_loss_counter18
  %18 = atomicrmw add ptr %lookup_elem22, i64 1 seq_cst, align 8
  br label %lookup_merge25

lookup_failure24:                                 ; preds = %event_loss_counter18
  br label %lookup_merge25

lookup_merge25:                                   ; preds = %lookup_failure24, %lookup_success23
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key21)
  br label %counter_merge19

helper_failure30:                                 ; preds = %lookup_merge9
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t32)
  %19 = getelementptr %helper_error_t, ptr %helper_error_t32, i64 0, i32 0
  store i64 30006, ptr %19, align 8
  %20 = getelementptr %helper_error_t, ptr %helper_error_t32, i64 0, i32 1
  store i64 2, ptr %20, align 8
  %21 = getelementptr %helper_error_t, ptr %helper_error_t32, i64 0, i32 2
  store i32 %13, ptr %21, align 4
  %ringbuf_output33 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t32, i64 20, i64 0)
  %ringbuf_loss36 = icmp slt i64 %ringbuf_output33, 0
  br i1 %ringbuf_loss36, label %event_loss_counter34, label %counter_merge35

helper_merge31:                                   ; preds = %counter_merge35, %lookup_merge9
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key29")
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
  %22 = atomicrmw add ptr %lookup_elem38, i64 1 seq_cst, align 8
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

; Function Attrs: alwaysinline
define internal i64 @log2(i64 %0, i64 %1) #2 section "helpers" {
entry:
  %2 = alloca i64, align 8
  %3 = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %3)
  store i64 %0, ptr %3, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %2)
  store i64 %1, ptr %2, align 8
  %4 = load i64, ptr %3, align 8
  %5 = icmp slt i64 %4, 0
  br i1 %5, label %hist.is_less_than_zero, label %hist.is_not_less_than_zero

hist.is_less_than_zero:                           ; preds = %entry
  ret i64 0

hist.is_not_less_than_zero:                       ; preds = %entry
  %6 = load i64, ptr %2, align 8
  %7 = shl i64 1, %6
  %8 = sub i64 %7, 1
  %9 = icmp ule i64 %4, %8
  br i1 %9, label %hist.is_zero, label %hist.is_not_zero

hist.is_zero:                                     ; preds = %hist.is_not_less_than_zero
  %10 = add i64 %4, 1
  ret i64 %10

hist.is_not_zero:                                 ; preds = %hist.is_not_less_than_zero
  %11 = icmp sge i64 %4, 4294967296
  %12 = zext i1 %11 to i64
  %13 = shl i64 %12, 5
  %14 = lshr i64 %4, %13
  %15 = add i64 0, %13
  %16 = icmp sge i64 %14, 65536
  %17 = zext i1 %16 to i64
  %18 = shl i64 %17, 4
  %19 = lshr i64 %14, %18
  %20 = add i64 %15, %18
  %21 = icmp sge i64 %19, 256
  %22 = zext i1 %21 to i64
  %23 = shl i64 %22, 3
  %24 = lshr i64 %19, %23
  %25 = add i64 %20, %23
  %26 = icmp sge i64 %24, 16
  %27 = zext i1 %26 to i64
  %28 = shl i64 %27, 2
  %29 = lshr i64 %24, %28
  %30 = add i64 %25, %28
  %31 = icmp sge i64 %29, 4
  %32 = zext i1 %31 to i64
  %33 = shl i64 %32, 1
  %34 = lshr i64 %29, %33
  %35 = add i64 %30, %33
  %36 = icmp sge i64 %34, 2
  %37 = zext i1 %36 to i64
  %38 = shl i64 %37, 0
  %39 = lshr i64 %34, %38
  %40 = add i64 %35, %38
  %41 = sub i64 %40, %6
  %42 = load i64, ptr %3, align 8
  %43 = lshr i64 %42, %41
  %44 = and i64 %43, %8
  %45 = add i64 %41, 1
  %46 = shl i64 %45, %6
  %47 = add i64 %46, %44
  %48 = add i64 %47, 1
  ret i64 %48
}

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #2 = { alwaysinline }

!llvm.dbg.cu = !{!55}
!llvm.module.flags = !{!57}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "AT_x", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !4)
!4 = !{!5, !11, !16, !19}
!5 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !6, size: 64)
!6 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !7, size: 64)
!7 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 160, elements: !9)
!8 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!9 = !{!10}
!10 = !DISubrange(count: 5, lowerBound: 0)
!11 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !12, size: 64, offset: 64)
!12 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !13, size: 64)
!13 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 131072, elements: !14)
!14 = !{!15}
!15 = !DISubrange(count: 4096, lowerBound: 0)
!16 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !17, size: 64, offset: 128)
!17 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !18, size: 64)
!18 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!19 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !17, size: 64, offset: 192)
!20 = !DIGlobalVariableExpression(var: !21, expr: !DIExpression())
!21 = distinct !DIGlobalVariable(name: "AT_y", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
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
!39 = !{!40, !45, !50, !19}
!40 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !41, size: 64)
!41 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !42, size: 64)
!42 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !43)
!43 = !{!44}
!44 = !DISubrange(count: 2, lowerBound: 0)
!45 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !46, size: 64, offset: 64)
!46 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !47, size: 64)
!47 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 32, elements: !48)
!48 = !{!49}
!49 = !DISubrange(count: 1, lowerBound: 0)
!50 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !51, size: 64, offset: 128)
!51 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !52, size: 64)
!52 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!53 = !DIGlobalVariableExpression(var: !54, expr: !DIExpression())
!54 = distinct !DIGlobalVariable(name: "num_cpus", linkageName: "global", scope: !2, file: !2, type: !18, isLocal: false, isDefinition: true)
!55 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !56)
!56 = !{!0, !20, !22, !36, !53}
!57 = !{i32 2, !"Debug Info Version", i32 3}
!58 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !59, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !55, retainedNodes: !63)
!59 = !DISubroutineType(types: !60)
!60 = !{!18, !61}
!61 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !62, size: 64)
!62 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!63 = !{!64}
!64 = !DILocalVariable(name: "ctx", arg: 1, scope: !58, file: !2, type: !61)
