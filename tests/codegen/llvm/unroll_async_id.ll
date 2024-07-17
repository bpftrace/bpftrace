; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr }
%"struct map_t.1" = type { ptr, ptr, ptr, ptr }
%printf_t.5 = type { i64 }
%printf_t.4 = type { i64 }
%printf_t.3 = type { i64 }
%printf_t.2 = type { i64 }
%printf_t = type { i64 }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_i = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@ringbuf = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !20
@event_loss_counter = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !34

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @BEGIN_1(ptr %0) section "s_BEGIN_1" !dbg !50 {
entry:
  %key39 = alloca i32, align 4
  %printf_args34 = alloca %printf_t.5, align 8
  %key28 = alloca i32, align 4
  %printf_args23 = alloca %printf_t.4, align 8
  %key17 = alloca i32, align 4
  %printf_args12 = alloca %printf_t.3, align 8
  %key6 = alloca i32, align 4
  %printf_args1 = alloca %printf_t.2, align 8
  %key = alloca i32, align 4
  %printf_args = alloca %printf_t, align 8
  %"@i_val" = alloca i64, align 8
  %"@i_key" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_key")
  store i64 0, ptr %"@i_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_val")
  store i64 0, ptr %"@i_val", align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_i, ptr %"@i_key", ptr %"@i_val", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %printf_args)
  call void @llvm.memset.p0.i64(ptr align 1 %printf_args, i8 0, i64 8, i1 false)
  %1 = getelementptr %printf_t, ptr %printf_args, i32 0, i32 0
  store i64 0, ptr %1, align 8
  %ringbuf_output = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %printf_args, i64 8, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

event_loss_counter:                               ; preds = %entry
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key)
  store i32 0, ptr %key, align 4
  %lookup_elem = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key)
  %map_lookup_cond = icmp ne ptr %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

counter_merge:                                    ; preds = %lookup_merge, %entry
  call void @llvm.lifetime.end.p0(i64 -1, ptr %printf_args)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %printf_args1)
  call void @llvm.memset.p0.i64(ptr align 1 %printf_args1, i8 0, i64 8, i1 false)
  %2 = getelementptr %printf_t.2, ptr %printf_args1, i32 0, i32 0
  store i64 0, ptr %2, align 8
  %ringbuf_output2 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %printf_args1, i64 8, i64 0)
  %ringbuf_loss5 = icmp slt i64 %ringbuf_output2, 0
  br i1 %ringbuf_loss5, label %event_loss_counter3, label %counter_merge4

lookup_success:                                   ; preds = %event_loss_counter
  %3 = atomicrmw add ptr %lookup_elem, i64 1 seq_cst, align 8
  br label %lookup_merge

lookup_failure:                                   ; preds = %event_loss_counter
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key)
  br label %counter_merge

event_loss_counter3:                              ; preds = %counter_merge
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key6)
  store i32 0, ptr %key6, align 4
  %lookup_elem7 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key6)
  %map_lookup_cond11 = icmp ne ptr %lookup_elem7, null
  br i1 %map_lookup_cond11, label %lookup_success8, label %lookup_failure9

counter_merge4:                                   ; preds = %lookup_merge10, %counter_merge
  call void @llvm.lifetime.end.p0(i64 -1, ptr %printf_args1)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %printf_args12)
  call void @llvm.memset.p0.i64(ptr align 1 %printf_args12, i8 0, i64 8, i1 false)
  %4 = getelementptr %printf_t.3, ptr %printf_args12, i32 0, i32 0
  store i64 0, ptr %4, align 8
  %ringbuf_output13 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %printf_args12, i64 8, i64 0)
  %ringbuf_loss16 = icmp slt i64 %ringbuf_output13, 0
  br i1 %ringbuf_loss16, label %event_loss_counter14, label %counter_merge15

lookup_success8:                                  ; preds = %event_loss_counter3
  %5 = atomicrmw add ptr %lookup_elem7, i64 1 seq_cst, align 8
  br label %lookup_merge10

lookup_failure9:                                  ; preds = %event_loss_counter3
  br label %lookup_merge10

lookup_merge10:                                   ; preds = %lookup_failure9, %lookup_success8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key6)
  br label %counter_merge4

event_loss_counter14:                             ; preds = %counter_merge4
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key17)
  store i32 0, ptr %key17, align 4
  %lookup_elem18 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key17)
  %map_lookup_cond22 = icmp ne ptr %lookup_elem18, null
  br i1 %map_lookup_cond22, label %lookup_success19, label %lookup_failure20

counter_merge15:                                  ; preds = %lookup_merge21, %counter_merge4
  call void @llvm.lifetime.end.p0(i64 -1, ptr %printf_args12)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %printf_args23)
  call void @llvm.memset.p0.i64(ptr align 1 %printf_args23, i8 0, i64 8, i1 false)
  %6 = getelementptr %printf_t.4, ptr %printf_args23, i32 0, i32 0
  store i64 0, ptr %6, align 8
  %ringbuf_output24 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %printf_args23, i64 8, i64 0)
  %ringbuf_loss27 = icmp slt i64 %ringbuf_output24, 0
  br i1 %ringbuf_loss27, label %event_loss_counter25, label %counter_merge26

lookup_success19:                                 ; preds = %event_loss_counter14
  %7 = atomicrmw add ptr %lookup_elem18, i64 1 seq_cst, align 8
  br label %lookup_merge21

lookup_failure20:                                 ; preds = %event_loss_counter14
  br label %lookup_merge21

lookup_merge21:                                   ; preds = %lookup_failure20, %lookup_success19
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key17)
  br label %counter_merge15

event_loss_counter25:                             ; preds = %counter_merge15
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key28)
  store i32 0, ptr %key28, align 4
  %lookup_elem29 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key28)
  %map_lookup_cond33 = icmp ne ptr %lookup_elem29, null
  br i1 %map_lookup_cond33, label %lookup_success30, label %lookup_failure31

counter_merge26:                                  ; preds = %lookup_merge32, %counter_merge15
  call void @llvm.lifetime.end.p0(i64 -1, ptr %printf_args23)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %printf_args34)
  call void @llvm.memset.p0.i64(ptr align 1 %printf_args34, i8 0, i64 8, i1 false)
  %8 = getelementptr %printf_t.5, ptr %printf_args34, i32 0, i32 0
  store i64 0, ptr %8, align 8
  %ringbuf_output35 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %printf_args34, i64 8, i64 0)
  %ringbuf_loss38 = icmp slt i64 %ringbuf_output35, 0
  br i1 %ringbuf_loss38, label %event_loss_counter36, label %counter_merge37

lookup_success30:                                 ; preds = %event_loss_counter25
  %9 = atomicrmw add ptr %lookup_elem29, i64 1 seq_cst, align 8
  br label %lookup_merge32

lookup_failure31:                                 ; preds = %event_loss_counter25
  br label %lookup_merge32

lookup_merge32:                                   ; preds = %lookup_failure31, %lookup_success30
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key28)
  br label %counter_merge26

event_loss_counter36:                             ; preds = %counter_merge26
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key39)
  store i32 0, ptr %key39, align 4
  %lookup_elem40 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key39)
  %map_lookup_cond44 = icmp ne ptr %lookup_elem40, null
  br i1 %map_lookup_cond44, label %lookup_success41, label %lookup_failure42

counter_merge37:                                  ; preds = %lookup_merge43, %counter_merge26
  call void @llvm.lifetime.end.p0(i64 -1, ptr %printf_args34)
  ret i64 0

lookup_success41:                                 ; preds = %event_loss_counter36
  %10 = atomicrmw add ptr %lookup_elem40, i64 1 seq_cst, align 8
  br label %lookup_merge43

lookup_failure42:                                 ; preds = %event_loss_counter36
  br label %lookup_merge43

lookup_merge43:                                   ; preds = %lookup_failure42, %lookup_success41
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key39)
  br label %counter_merge37
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #2 = { nocallback nofree nounwind willreturn memory(argmem: write) }

!llvm.dbg.cu = !{!47}
!llvm.module.flags = !{!49}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "AT_i", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !4)
!4 = !{!5, !11, !16, !19}
!5 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !6, size: 64)
!6 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !7, size: 64)
!7 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 32, elements: !9)
!8 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!9 = !{!10}
!10 = !DISubrange(count: 1, lowerBound: 0)
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
!21 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !22, isLocal: false, isDefinition: true)
!22 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !23)
!23 = !{!24, !29}
!24 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !25, size: 64)
!25 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !26, size: 64)
!26 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !27)
!27 = !{!28}
!28 = !DISubrange(count: 27, lowerBound: 0)
!29 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !30, size: 64, offset: 64)
!30 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !31, size: 64)
!31 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !32)
!32 = !{!33}
!33 = !DISubrange(count: 262144, lowerBound: 0)
!34 = !DIGlobalVariableExpression(var: !35, expr: !DIExpression())
!35 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !36, isLocal: false, isDefinition: true)
!36 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !37)
!37 = !{!38, !43, !44, !19}
!38 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !39, size: 64)
!39 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !40, size: 64)
!40 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !41)
!41 = !{!42}
!42 = !DISubrange(count: 2, lowerBound: 0)
!43 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !6, size: 64, offset: 64)
!44 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !45, size: 64, offset: 128)
!45 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !46, size: 64)
!46 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!47 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !48)
!48 = !{!0, !20, !34}
!49 = !{i32 2, !"Debug Info Version", i32 3}
!50 = distinct !DISubprogram(name: "BEGIN_1", linkageName: "BEGIN_1", scope: !2, file: !2, type: !51, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !47, retainedNodes: !55)
!51 = !DISubroutineType(types: !52)
!52 = !{!18, !53}
!53 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !54, size: 64)
!54 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!55 = !{!56}
!56 = !DILocalVariable(name: "ctx", arg: 1, scope: !50, file: !2, type: !53)
