; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr }
%"struct map_t.1" = type { ptr, ptr, ptr, ptr }
%"struct map_t.2" = type { ptr, ptr, ptr, ptr }
%"struct map_t.3" = type { ptr, ptr, ptr, ptr }
%printf_t = type { i64 }
%printf_t.4 = type { i64 }
%printf_t.5 = type { i64 }
%printf_t.6 = type { i64 }
%printf_t.7 = type { i64 }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_i = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@ringbuf = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !22
@event_loss_counter = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !36
@stack = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !38
@fmt_string_args = dso_local global %"struct map_t.3" zeroinitializer, section ".maps", !dbg !53

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @BEGIN_1(ptr %0) section "s_BEGIN_1" !dbg !65 {
entry:
  %key55 = alloca i32, align 4
  %lookup_fmtstr_key46 = alloca i32, align 4
  %key40 = alloca i32, align 4
  %lookup_fmtstr_key31 = alloca i32, align 4
  %key25 = alloca i32, align 4
  %lookup_fmtstr_key16 = alloca i32, align 4
  %key10 = alloca i32, align 4
  %lookup_fmtstr_key1 = alloca i32, align 4
  %key = alloca i32, align 4
  %lookup_fmtstr_key = alloca i32, align 4
  %"@i_val" = alloca i64, align 8
  %"@i_key" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_key")
  store i64 0, ptr %"@i_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_val")
  store i64 0, ptr %"@i_val", align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_i, ptr %"@i_key", ptr %"@i_val", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_fmtstr_key)
  store i32 0, ptr %lookup_fmtstr_key, align 4
  %lookup_fmtstr_map = call ptr inttoptr (i64 1 to ptr)(ptr @fmt_string_args, ptr %lookup_fmtstr_key)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_fmtstr_key)
  %lookup_fmtstr_cond = icmp ne ptr %lookup_fmtstr_map, null
  br i1 %lookup_fmtstr_cond, label %lookup_fmtstr_merge, label %lookup_fmtstr_failure

lookup_fmtstr_failure:                            ; preds = %entry
  ret i64 0

lookup_fmtstr_merge:                              ; preds = %entry
  call void @llvm.memset.p0.i64(ptr align 1 %lookup_fmtstr_map, i8 0, i64 8, i1 false)
  %1 = getelementptr %printf_t, ptr %lookup_fmtstr_map, i32 0, i32 0
  store i64 0, ptr %1, align 8
  %ringbuf_output = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %lookup_fmtstr_map, i64 8, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

event_loss_counter:                               ; preds = %lookup_fmtstr_merge
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key)
  store i32 0, ptr %key, align 4
  %lookup_elem = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key)
  %map_lookup_cond = icmp ne ptr %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

counter_merge:                                    ; preds = %lookup_merge, %lookup_fmtstr_merge
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_fmtstr_key1)
  store i32 0, ptr %lookup_fmtstr_key1, align 4
  %lookup_fmtstr_map2 = call ptr inttoptr (i64 1 to ptr)(ptr @fmt_string_args, ptr %lookup_fmtstr_key1)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_fmtstr_key1)
  %lookup_fmtstr_cond5 = icmp ne ptr %lookup_fmtstr_map2, null
  br i1 %lookup_fmtstr_cond5, label %lookup_fmtstr_merge4, label %lookup_fmtstr_failure3

lookup_success:                                   ; preds = %event_loss_counter
  %2 = atomicrmw add ptr %lookup_elem, i64 1 seq_cst, align 8
  br label %lookup_merge

lookup_failure:                                   ; preds = %event_loss_counter
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key)
  br label %counter_merge

lookup_fmtstr_failure3:                           ; preds = %counter_merge
  ret i64 0

lookup_fmtstr_merge4:                             ; preds = %counter_merge
  call void @llvm.memset.p0.i64(ptr align 1 %lookup_fmtstr_map2, i8 0, i64 8, i1 false)
  %3 = getelementptr %printf_t.4, ptr %lookup_fmtstr_map2, i32 0, i32 0
  store i64 0, ptr %3, align 8
  %ringbuf_output6 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %lookup_fmtstr_map2, i64 8, i64 0)
  %ringbuf_loss9 = icmp slt i64 %ringbuf_output6, 0
  br i1 %ringbuf_loss9, label %event_loss_counter7, label %counter_merge8

event_loss_counter7:                              ; preds = %lookup_fmtstr_merge4
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key10)
  store i32 0, ptr %key10, align 4
  %lookup_elem11 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key10)
  %map_lookup_cond15 = icmp ne ptr %lookup_elem11, null
  br i1 %map_lookup_cond15, label %lookup_success12, label %lookup_failure13

counter_merge8:                                   ; preds = %lookup_merge14, %lookup_fmtstr_merge4
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_fmtstr_key16)
  store i32 0, ptr %lookup_fmtstr_key16, align 4
  %lookup_fmtstr_map17 = call ptr inttoptr (i64 1 to ptr)(ptr @fmt_string_args, ptr %lookup_fmtstr_key16)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_fmtstr_key16)
  %lookup_fmtstr_cond20 = icmp ne ptr %lookup_fmtstr_map17, null
  br i1 %lookup_fmtstr_cond20, label %lookup_fmtstr_merge19, label %lookup_fmtstr_failure18

lookup_success12:                                 ; preds = %event_loss_counter7
  %4 = atomicrmw add ptr %lookup_elem11, i64 1 seq_cst, align 8
  br label %lookup_merge14

lookup_failure13:                                 ; preds = %event_loss_counter7
  br label %lookup_merge14

lookup_merge14:                                   ; preds = %lookup_failure13, %lookup_success12
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key10)
  br label %counter_merge8

lookup_fmtstr_failure18:                          ; preds = %counter_merge8
  ret i64 0

lookup_fmtstr_merge19:                            ; preds = %counter_merge8
  call void @llvm.memset.p0.i64(ptr align 1 %lookup_fmtstr_map17, i8 0, i64 8, i1 false)
  %5 = getelementptr %printf_t.5, ptr %lookup_fmtstr_map17, i32 0, i32 0
  store i64 0, ptr %5, align 8
  %ringbuf_output21 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %lookup_fmtstr_map17, i64 8, i64 0)
  %ringbuf_loss24 = icmp slt i64 %ringbuf_output21, 0
  br i1 %ringbuf_loss24, label %event_loss_counter22, label %counter_merge23

event_loss_counter22:                             ; preds = %lookup_fmtstr_merge19
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key25)
  store i32 0, ptr %key25, align 4
  %lookup_elem26 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key25)
  %map_lookup_cond30 = icmp ne ptr %lookup_elem26, null
  br i1 %map_lookup_cond30, label %lookup_success27, label %lookup_failure28

counter_merge23:                                  ; preds = %lookup_merge29, %lookup_fmtstr_merge19
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_fmtstr_key31)
  store i32 0, ptr %lookup_fmtstr_key31, align 4
  %lookup_fmtstr_map32 = call ptr inttoptr (i64 1 to ptr)(ptr @fmt_string_args, ptr %lookup_fmtstr_key31)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_fmtstr_key31)
  %lookup_fmtstr_cond35 = icmp ne ptr %lookup_fmtstr_map32, null
  br i1 %lookup_fmtstr_cond35, label %lookup_fmtstr_merge34, label %lookup_fmtstr_failure33

lookup_success27:                                 ; preds = %event_loss_counter22
  %6 = atomicrmw add ptr %lookup_elem26, i64 1 seq_cst, align 8
  br label %lookup_merge29

lookup_failure28:                                 ; preds = %event_loss_counter22
  br label %lookup_merge29

lookup_merge29:                                   ; preds = %lookup_failure28, %lookup_success27
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key25)
  br label %counter_merge23

lookup_fmtstr_failure33:                          ; preds = %counter_merge23
  ret i64 0

lookup_fmtstr_merge34:                            ; preds = %counter_merge23
  call void @llvm.memset.p0.i64(ptr align 1 %lookup_fmtstr_map32, i8 0, i64 8, i1 false)
  %7 = getelementptr %printf_t.6, ptr %lookup_fmtstr_map32, i32 0, i32 0
  store i64 0, ptr %7, align 8
  %ringbuf_output36 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %lookup_fmtstr_map32, i64 8, i64 0)
  %ringbuf_loss39 = icmp slt i64 %ringbuf_output36, 0
  br i1 %ringbuf_loss39, label %event_loss_counter37, label %counter_merge38

event_loss_counter37:                             ; preds = %lookup_fmtstr_merge34
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key40)
  store i32 0, ptr %key40, align 4
  %lookup_elem41 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key40)
  %map_lookup_cond45 = icmp ne ptr %lookup_elem41, null
  br i1 %map_lookup_cond45, label %lookup_success42, label %lookup_failure43

counter_merge38:                                  ; preds = %lookup_merge44, %lookup_fmtstr_merge34
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_fmtstr_key46)
  store i32 0, ptr %lookup_fmtstr_key46, align 4
  %lookup_fmtstr_map47 = call ptr inttoptr (i64 1 to ptr)(ptr @fmt_string_args, ptr %lookup_fmtstr_key46)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_fmtstr_key46)
  %lookup_fmtstr_cond50 = icmp ne ptr %lookup_fmtstr_map47, null
  br i1 %lookup_fmtstr_cond50, label %lookup_fmtstr_merge49, label %lookup_fmtstr_failure48

lookup_success42:                                 ; preds = %event_loss_counter37
  %8 = atomicrmw add ptr %lookup_elem41, i64 1 seq_cst, align 8
  br label %lookup_merge44

lookup_failure43:                                 ; preds = %event_loss_counter37
  br label %lookup_merge44

lookup_merge44:                                   ; preds = %lookup_failure43, %lookup_success42
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key40)
  br label %counter_merge38

lookup_fmtstr_failure48:                          ; preds = %counter_merge38
  ret i64 0

lookup_fmtstr_merge49:                            ; preds = %counter_merge38
  call void @llvm.memset.p0.i64(ptr align 1 %lookup_fmtstr_map47, i8 0, i64 8, i1 false)
  %9 = getelementptr %printf_t.7, ptr %lookup_fmtstr_map47, i32 0, i32 0
  store i64 0, ptr %9, align 8
  %ringbuf_output51 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %lookup_fmtstr_map47, i64 8, i64 0)
  %ringbuf_loss54 = icmp slt i64 %ringbuf_output51, 0
  br i1 %ringbuf_loss54, label %event_loss_counter52, label %counter_merge53

event_loss_counter52:                             ; preds = %lookup_fmtstr_merge49
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key55)
  store i32 0, ptr %key55, align 4
  %lookup_elem56 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key55)
  %map_lookup_cond60 = icmp ne ptr %lookup_elem56, null
  br i1 %map_lookup_cond60, label %lookup_success57, label %lookup_failure58

counter_merge53:                                  ; preds = %lookup_merge59, %lookup_fmtstr_merge49
  ret i64 0

lookup_success57:                                 ; preds = %event_loss_counter52
  %10 = atomicrmw add ptr %lookup_elem56, i64 1 seq_cst, align 8
  br label %lookup_merge59

lookup_failure58:                                 ; preds = %event_loss_counter52
  br label %lookup_merge59

lookup_merge59:                                   ; preds = %lookup_failure58, %lookup_success57
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key55)
  br label %counter_merge53
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

!llvm.dbg.cu = !{!62}
!llvm.module.flags = !{!64}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "AT_i", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !4)
!4 = !{!5, !11, !16, !19}
!5 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !6, size: 64)
!6 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !7, size: 64)
!7 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !9)
!8 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!9 = !{!10}
!10 = !DISubrange(count: 2, lowerBound: 0)
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
!37 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!38 = !DIGlobalVariableExpression(var: !39, expr: !DIExpression())
!39 = distinct !DIGlobalVariable(name: "stack", linkageName: "global", scope: !2, file: !2, type: !40, isLocal: false, isDefinition: true)
!40 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !41)
!41 = !{!42, !11, !16, !47}
!42 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !43, size: 64)
!43 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !44, size: 64)
!44 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 192, elements: !45)
!45 = !{!46}
!46 = !DISubrange(count: 6, lowerBound: 0)
!47 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !48, size: 64, offset: 192)
!48 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !49, size: 64)
!49 = !DICompositeType(tag: DW_TAG_array_type, baseType: !50, size: 32768, elements: !51)
!50 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!51 = !{!52}
!52 = !DISubrange(count: 4096, lowerBound: 0)
!53 = !DIGlobalVariableExpression(var: !54, expr: !DIExpression())
!54 = distinct !DIGlobalVariable(name: "fmt_string_args", linkageName: "global", scope: !2, file: !2, type: !55, isLocal: false, isDefinition: true)
!55 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !56)
!56 = !{!42, !11, !16, !57}
!57 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !58, size: 64, offset: 192)
!58 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !59, size: 64)
!59 = !DICompositeType(tag: DW_TAG_array_type, baseType: !50, size: 64, elements: !60)
!60 = !{!61}
!61 = !DISubrange(count: 8, lowerBound: 0)
!62 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !63)
!63 = !{!0, !22, !36, !38, !53}
!64 = !{i32 2, !"Debug Info Version", i32 3}
!65 = distinct !DISubprogram(name: "BEGIN_1", linkageName: "BEGIN_1", scope: !2, file: !2, type: !66, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !62, retainedNodes: !69)
!66 = !DISubroutineType(types: !67)
!67 = !{!21, !68}
!68 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !50, size: 64)
!69 = !{!70}
!70 = !DILocalVariable(name: "ctx", arg: 1, scope: !65, file: !2, type: !68)
