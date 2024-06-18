; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr }
%"struct map_t.0" = type { ptr, ptr, ptr, ptr }
%"struct map_t.1" = type { ptr, ptr, ptr, ptr }
%printf_t = type { i64, i64 }
%printf_t.2 = type { i64, i64 }
%printf_t.3 = type { i64, i64 }
%printf_t.4 = type { i64, i64 }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@ringbuf = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@event_loss_counter = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !16
@fmt_string_args = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !36

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @BEGIN_1(ptr %0) section "s_BEGIN_1" !dbg !54 {
entry:
  %key40 = alloca i32, align 4
  %lookup_fmtstr_key31 = alloca i32, align 4
  %key25 = alloca i32, align 4
  %lookup_fmtstr_key16 = alloca i32, align 4
  %key10 = alloca i32, align 4
  %lookup_fmtstr_key1 = alloca i32, align 4
  %key = alloca i32, align 4
  %lookup_fmtstr_key = alloca i32, align 4
  %"$x" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$x")
  store i64 0, ptr %"$x", align 8
  store i64 10, ptr %"$x", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_fmtstr_key)
  store i32 0, ptr %lookup_fmtstr_key, align 4
  %lookup_fmtstr_map = call ptr inttoptr (i64 1 to ptr)(ptr @fmt_string_args, ptr %lookup_fmtstr_key)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_fmtstr_key)
  %lookup_fmtstr_cond = icmp ne ptr %lookup_fmtstr_map, null
  br i1 %lookup_fmtstr_cond, label %lookup_fmtstr_merge, label %lookup_fmtstr_failure

lookup_fmtstr_failure:                            ; preds = %entry
  ret i64 0

lookup_fmtstr_merge:                              ; preds = %entry
  call void @llvm.memset.p0.i64(ptr align 1 %lookup_fmtstr_map, i8 0, i64 16, i1 false)
  %1 = getelementptr %printf_t, ptr %lookup_fmtstr_map, i32 0, i32 0
  store i64 0, ptr %1, align 8
  %2 = load i64, ptr %"$x", align 8
  %3 = add i64 %2, 1
  store i64 %3, ptr %"$x", align 8
  %4 = getelementptr %printf_t, ptr %lookup_fmtstr_map, i32 0, i32 1
  store i64 %2, ptr %4, align 8
  %ringbuf_output = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %lookup_fmtstr_map, i64 16, i64 0)
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
  %5 = atomicrmw add ptr %lookup_elem, i64 1 seq_cst, align 8
  br label %lookup_merge

lookup_failure:                                   ; preds = %event_loss_counter
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key)
  br label %counter_merge

lookup_fmtstr_failure3:                           ; preds = %counter_merge
  ret i64 0

lookup_fmtstr_merge4:                             ; preds = %counter_merge
  call void @llvm.memset.p0.i64(ptr align 1 %lookup_fmtstr_map2, i8 0, i64 16, i1 false)
  %6 = getelementptr %printf_t.2, ptr %lookup_fmtstr_map2, i32 0, i32 0
  store i64 1, ptr %6, align 8
  %7 = load i64, ptr %"$x", align 8
  %8 = add i64 %7, 1
  store i64 %8, ptr %"$x", align 8
  %9 = getelementptr %printf_t.2, ptr %lookup_fmtstr_map2, i32 0, i32 1
  store i64 %8, ptr %9, align 8
  %ringbuf_output6 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %lookup_fmtstr_map2, i64 16, i64 0)
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
  %10 = atomicrmw add ptr %lookup_elem11, i64 1 seq_cst, align 8
  br label %lookup_merge14

lookup_failure13:                                 ; preds = %event_loss_counter7
  br label %lookup_merge14

lookup_merge14:                                   ; preds = %lookup_failure13, %lookup_success12
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key10)
  br label %counter_merge8

lookup_fmtstr_failure18:                          ; preds = %counter_merge8
  ret i64 0

lookup_fmtstr_merge19:                            ; preds = %counter_merge8
  call void @llvm.memset.p0.i64(ptr align 1 %lookup_fmtstr_map17, i8 0, i64 16, i1 false)
  %11 = getelementptr %printf_t.3, ptr %lookup_fmtstr_map17, i32 0, i32 0
  store i64 2, ptr %11, align 8
  %12 = load i64, ptr %"$x", align 8
  %13 = sub i64 %12, 1
  store i64 %13, ptr %"$x", align 8
  %14 = getelementptr %printf_t.3, ptr %lookup_fmtstr_map17, i32 0, i32 1
  store i64 %12, ptr %14, align 8
  %ringbuf_output21 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %lookup_fmtstr_map17, i64 16, i64 0)
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
  %15 = atomicrmw add ptr %lookup_elem26, i64 1 seq_cst, align 8
  br label %lookup_merge29

lookup_failure28:                                 ; preds = %event_loss_counter22
  br label %lookup_merge29

lookup_merge29:                                   ; preds = %lookup_failure28, %lookup_success27
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key25)
  br label %counter_merge23

lookup_fmtstr_failure33:                          ; preds = %counter_merge23
  ret i64 0

lookup_fmtstr_merge34:                            ; preds = %counter_merge23
  call void @llvm.memset.p0.i64(ptr align 1 %lookup_fmtstr_map32, i8 0, i64 16, i1 false)
  %16 = getelementptr %printf_t.4, ptr %lookup_fmtstr_map32, i32 0, i32 0
  store i64 3, ptr %16, align 8
  %17 = load i64, ptr %"$x", align 8
  %18 = sub i64 %17, 1
  store i64 %18, ptr %"$x", align 8
  %19 = getelementptr %printf_t.4, ptr %lookup_fmtstr_map32, i32 0, i32 1
  store i64 %18, ptr %19, align 8
  %ringbuf_output36 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %lookup_fmtstr_map32, i64 16, i64 0)
  %ringbuf_loss39 = icmp slt i64 %ringbuf_output36, 0
  br i1 %ringbuf_loss39, label %event_loss_counter37, label %counter_merge38

event_loss_counter37:                             ; preds = %lookup_fmtstr_merge34
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key40)
  store i32 0, ptr %key40, align 4
  %lookup_elem41 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key40)
  %map_lookup_cond45 = icmp ne ptr %lookup_elem41, null
  br i1 %map_lookup_cond45, label %lookup_success42, label %lookup_failure43

counter_merge38:                                  ; preds = %lookup_merge44, %lookup_fmtstr_merge34
  ret i64 0

lookup_success42:                                 ; preds = %event_loss_counter37
  %20 = atomicrmw add ptr %lookup_elem41, i64 1 seq_cst, align 8
  br label %lookup_merge44

lookup_failure43:                                 ; preds = %event_loss_counter37
  br label %lookup_merge44

lookup_merge44:                                   ; preds = %lookup_failure43, %lookup_success42
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key40)
  br label %counter_merge38
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

!llvm.dbg.cu = !{!51}
!llvm.module.flags = !{!53}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !4)
!4 = !{!5, !11}
!5 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !6, size: 64)
!6 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !7, size: 64)
!7 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !9)
!8 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!9 = !{!10}
!10 = !DISubrange(count: 27, lowerBound: 0)
!11 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !12, size: 64, offset: 64)
!12 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !13, size: 64)
!13 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !14)
!14 = !{!15}
!15 = !DISubrange(count: 262144, lowerBound: 0)
!16 = !DIGlobalVariableExpression(var: !17, expr: !DIExpression())
!17 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !18, isLocal: false, isDefinition: true)
!18 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !19)
!19 = !{!20, !25, !30, !33}
!20 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !21, size: 64)
!21 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !22, size: 64)
!22 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !23)
!23 = !{!24}
!24 = !DISubrange(count: 2, lowerBound: 0)
!25 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !26, size: 64, offset: 64)
!26 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !27, size: 64)
!27 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 32, elements: !28)
!28 = !{!29}
!29 = !DISubrange(count: 1, lowerBound: 0)
!30 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !31, size: 64, offset: 128)
!31 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !32, size: 64)
!32 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!33 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !34, size: 64, offset: 192)
!34 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !35, size: 64)
!35 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!36 = !DIGlobalVariableExpression(var: !37, expr: !DIExpression())
!37 = distinct !DIGlobalVariable(name: "fmt_string_args", linkageName: "global", scope: !2, file: !2, type: !38, isLocal: false, isDefinition: true)
!38 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !39)
!39 = !{!40, !25, !30, !45}
!40 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !41, size: 64)
!41 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !42, size: 64)
!42 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 192, elements: !43)
!43 = !{!44}
!44 = !DISubrange(count: 6, lowerBound: 0)
!45 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !46, size: 64, offset: 192)
!46 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !47, size: 64)
!47 = !DICompositeType(tag: DW_TAG_array_type, baseType: !48, size: 128, elements: !49)
!48 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!49 = !{!50}
!50 = !DISubrange(count: 16, lowerBound: 0)
!51 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !52)
!52 = !{!0, !16, !36}
!53 = !{i32 2, !"Debug Info Version", i32 3}
!54 = distinct !DISubprogram(name: "BEGIN_1", linkageName: "BEGIN_1", scope: !2, file: !2, type: !55, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !51, retainedNodes: !58)
!55 = !DISubroutineType(types: !56)
!56 = !{!35, !57}
!57 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !48, size: 64)
!58 = !{!59}
!59 = !DILocalVariable(name: "ctx", arg: 1, scope: !54, file: !2, type: !57)
