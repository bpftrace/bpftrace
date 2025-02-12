; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr, ptr, ptr }
%"struct map_t.1" = type { ptr, ptr }
%"struct map_t.2" = type { ptr, ptr, ptr, ptr }
%helper_error_t = type <{ i64, i64, i32 }>
%"string[8]_int64__tuple_t" = type { [8 x i8], i64 }
%"string[4]_int64__tuple_t" = type { [4 x i8], i64 }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_x = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@AT_y = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !25
@ringbuf = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !27
@event_loss_counter = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !41
@xxx = global [4 x i8] c"xxx\00"
@xxxxxxx = global [8 x i8] c"xxxxxxx\00"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(ptr %0) section "s_kprobe_f_1" !dbg !57 {
entry:
  %key31 = alloca i32, align 4
  %helper_error_t26 = alloca %helper_error_t, align 8
  %"@y_key" = alloca i64, align 8
  %lookup_elem_val = alloca %"string[8]_int64__tuple_t", align 8
  %"@x_key17" = alloca i64, align 8
  %key11 = alloca i32, align 4
  %helper_error_t6 = alloca %helper_error_t, align 8
  %"@x_key2" = alloca i64, align 8
  %tuple1 = alloca %"string[8]_int64__tuple_t", align 8
  %key = alloca i32, align 4
  %helper_error_t = alloca %helper_error_t, align 8
  %"@x_val" = alloca %"string[8]_int64__tuple_t", align 8
  %"@x_key" = alloca i64, align 8
  %tuple = alloca %"string[4]_int64__tuple_t", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %tuple)
  call void @llvm.memset.p0.i64(ptr align 1 %tuple, i8 0, i64 16, i1 false)
  %1 = getelementptr %"string[4]_int64__tuple_t", ptr %tuple, i32 0, i32 0
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %1, ptr align 1 @xxx, i64 4, i1 false)
  %2 = getelementptr %"string[4]_int64__tuple_t", ptr %tuple, i32 0, i32 1
  store i64 1, ptr %2, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key")
  store i64 0, ptr %"@x_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_val")
  call void @llvm.memset.p0.i64(ptr align 1 %"@x_val", i8 0, i64 16, i1 false)
  %3 = getelementptr [16 x i8], ptr %tuple, i64 0, i64 0
  %4 = getelementptr %"string[8]_int64__tuple_t", ptr %"@x_val", i32 0, i32 0
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %4, ptr align 1 %3, i64 4, i1 false)
  %5 = getelementptr [16 x i8], ptr %tuple, i64 0, i64 8
  %6 = getelementptr %"string[8]_int64__tuple_t", ptr %"@x_val", i32 0, i32 1
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %6, ptr align 1 %5, i64 8, i1 false)
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %"@x_key", ptr %"@x_val", i64 0)
  %7 = trunc i64 %update_elem to i32
  %8 = icmp sge i32 %7, 0
  br i1 %8, label %helper_merge, label %helper_failure

helper_failure:                                   ; preds = %entry
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t)
  %9 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 0
  store i64 30006, ptr %9, align 8
  %10 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 1
  store i64 0, ptr %10, align 8
  %11 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 2
  store i32 %7, ptr %11, align 4
  %ringbuf_output = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t, i64 20, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

helper_merge:                                     ; preds = %counter_merge, %entry
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %tuple)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %tuple1)
  call void @llvm.memset.p0.i64(ptr align 1 %tuple1, i8 0, i64 16, i1 false)
  %12 = getelementptr %"string[8]_int64__tuple_t", ptr %tuple1, i32 0, i32 0
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %12, ptr align 1 @xxxxxxx, i64 8, i1 false)
  %13 = getelementptr %"string[8]_int64__tuple_t", ptr %tuple1, i32 0, i32 1
  store i64 1, ptr %13, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key2")
  store i64 0, ptr %"@x_key2", align 8
  %update_elem3 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %"@x_key2", ptr %tuple1, i64 0)
  %14 = trunc i64 %update_elem3 to i32
  %15 = icmp sge i32 %14, 0
  br i1 %15, label %helper_merge5, label %helper_failure4

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
  %16 = atomicrmw add ptr %lookup_elem, i64 1 seq_cst, align 8
  br label %lookup_merge

lookup_failure:                                   ; preds = %event_loss_counter
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key)
  br label %counter_merge

helper_failure4:                                  ; preds = %helper_merge
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t6)
  %17 = getelementptr %helper_error_t, ptr %helper_error_t6, i64 0, i32 0
  store i64 30006, ptr %17, align 8
  %18 = getelementptr %helper_error_t, ptr %helper_error_t6, i64 0, i32 1
  store i64 1, ptr %18, align 8
  %19 = getelementptr %helper_error_t, ptr %helper_error_t6, i64 0, i32 2
  store i32 %14, ptr %19, align 4
  %ringbuf_output7 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t6, i64 20, i64 0)
  %ringbuf_loss10 = icmp slt i64 %ringbuf_output7, 0
  br i1 %ringbuf_loss10, label %event_loss_counter8, label %counter_merge9

helper_merge5:                                    ; preds = %counter_merge9, %helper_merge
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key2")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %tuple1)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key17")
  store i64 0, ptr %"@x_key17", align 8
  %lookup_elem18 = call ptr inttoptr (i64 1 to ptr)(ptr @AT_x, ptr %"@x_key17")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_elem_val)
  %map_lookup_cond22 = icmp ne ptr %lookup_elem18, null
  br i1 %map_lookup_cond22, label %lookup_success19, label %lookup_failure20

event_loss_counter8:                              ; preds = %helper_failure4
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key11)
  store i32 0, ptr %key11, align 4
  %lookup_elem12 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key11)
  %map_lookup_cond16 = icmp ne ptr %lookup_elem12, null
  br i1 %map_lookup_cond16, label %lookup_success13, label %lookup_failure14

counter_merge9:                                   ; preds = %lookup_merge15, %helper_failure4
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t6)
  br label %helper_merge5

lookup_success13:                                 ; preds = %event_loss_counter8
  %20 = atomicrmw add ptr %lookup_elem12, i64 1 seq_cst, align 8
  br label %lookup_merge15

lookup_failure14:                                 ; preds = %event_loss_counter8
  br label %lookup_merge15

lookup_merge15:                                   ; preds = %lookup_failure14, %lookup_success13
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key11)
  br label %counter_merge9

lookup_success19:                                 ; preds = %helper_merge5
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %lookup_elem_val, ptr align 1 %lookup_elem18, i64 16, i1 false)
  br label %lookup_merge21

lookup_failure20:                                 ; preds = %helper_merge5
  call void @llvm.memset.p0.i64(ptr align 1 %lookup_elem_val, i8 0, i64 16, i1 false)
  br label %lookup_merge21

lookup_merge21:                                   ; preds = %lookup_failure20, %lookup_success19
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key17")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@y_key")
  store i64 0, ptr %"@y_key", align 8
  %update_elem23 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_y, ptr %"@y_key", ptr %lookup_elem_val, i64 0)
  %21 = trunc i64 %update_elem23 to i32
  %22 = icmp sge i32 %21, 0
  br i1 %22, label %helper_merge25, label %helper_failure24

helper_failure24:                                 ; preds = %lookup_merge21
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t26)
  %23 = getelementptr %helper_error_t, ptr %helper_error_t26, i64 0, i32 0
  store i64 30006, ptr %23, align 8
  %24 = getelementptr %helper_error_t, ptr %helper_error_t26, i64 0, i32 1
  store i64 2, ptr %24, align 8
  %25 = getelementptr %helper_error_t, ptr %helper_error_t26, i64 0, i32 2
  store i32 %21, ptr %25, align 4
  %ringbuf_output27 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t26, i64 20, i64 0)
  %ringbuf_loss30 = icmp slt i64 %ringbuf_output27, 0
  br i1 %ringbuf_loss30, label %event_loss_counter28, label %counter_merge29

helper_merge25:                                   ; preds = %counter_merge29, %lookup_merge21
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@y_key")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_elem_val)
  ret i64 0

event_loss_counter28:                             ; preds = %helper_failure24
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key31)
  store i32 0, ptr %key31, align 4
  %lookup_elem32 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key31)
  %map_lookup_cond36 = icmp ne ptr %lookup_elem32, null
  br i1 %map_lookup_cond36, label %lookup_success33, label %lookup_failure34

counter_merge29:                                  ; preds = %lookup_merge35, %helper_failure24
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t26)
  br label %helper_merge25

lookup_success33:                                 ; preds = %event_loss_counter28
  %26 = atomicrmw add ptr %lookup_elem32, i64 1 seq_cst, align 8
  br label %lookup_merge35

lookup_failure34:                                 ; preds = %event_loss_counter28
  br label %lookup_merge35

lookup_merge35:                                   ; preds = %lookup_failure34, %lookup_success33
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key31)
  br label %counter_merge29
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: readwrite)
declare void @llvm.memcpy.p0.p0.i64(ptr noalias nocapture writeonly %0, ptr noalias nocapture readonly %1, i64 %2, i1 immarg %3) #3

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #2 = { nocallback nofree nounwind willreturn memory(argmem: write) }
attributes #3 = { nocallback nofree nounwind willreturn memory(argmem: readwrite) }

!llvm.dbg.cu = !{!54}
!llvm.module.flags = !{!56}

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
!15 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !16, size: 64, offset: 192)
!16 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !17, size: 64)
!17 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !18)
!18 = !{!19, !24}
!19 = !DIDerivedType(tag: DW_TAG_member, scope: !2, file: !2, baseType: !20, size: 64)
!20 = !DICompositeType(tag: DW_TAG_array_type, baseType: !21, size: 64, elements: !22)
!21 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!22 = !{!23}
!23 = !DISubrange(count: 8, lowerBound: 0)
!24 = !DIDerivedType(tag: DW_TAG_member, scope: !2, file: !2, baseType: !14, size: 64, offset: 64)
!25 = !DIGlobalVariableExpression(var: !26, expr: !DIExpression())
!26 = distinct !DIGlobalVariable(name: "AT_y", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!27 = !DIGlobalVariableExpression(var: !28, expr: !DIExpression())
!28 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !29, isLocal: false, isDefinition: true)
!29 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !30)
!30 = !{!31, !36}
!31 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !32, size: 64)
!32 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !33, size: 64)
!33 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !34)
!34 = !{!35}
!35 = !DISubrange(count: 27, lowerBound: 0)
!36 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !37, size: 64, offset: 64)
!37 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !38, size: 64)
!38 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !39)
!39 = !{!40}
!40 = !DISubrange(count: 262144, lowerBound: 0)
!41 = !DIGlobalVariableExpression(var: !42, expr: !DIExpression())
!42 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !43, isLocal: false, isDefinition: true)
!43 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !44)
!44 = !{!45, !11, !50, !53}
!45 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !46, size: 64)
!46 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !47, size: 64)
!47 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !48)
!48 = !{!49}
!49 = !DISubrange(count: 2, lowerBound: 0)
!50 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !51, size: 64, offset: 128)
!51 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !52, size: 64)
!52 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!53 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !13, size: 64, offset: 192)
!54 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !55)
!55 = !{!0, !25, !27, !41}
!56 = !{i32 2, !"Debug Info Version", i32 3}
!57 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !58, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !54, retainedNodes: !61)
!58 = !DISubroutineType(types: !59)
!59 = !{!14, !60}
!60 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !21, size: 64)
!61 = !{!62}
!62 = !DILocalVariable(name: "ctx", arg: 1, scope: !57, file: !2, type: !60)
