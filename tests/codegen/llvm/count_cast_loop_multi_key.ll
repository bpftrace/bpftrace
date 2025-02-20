; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr }
%"struct map_t.1" = type { ptr, ptr, ptr, ptr }
%helper_error_t = type <{ i64, i64, i32 }>
%int64_int64__tuple_t = type { i64, i64 }
%"(int64,int64)_count_t__tuple_t" = type { %int64_int64__tuple_t, i64 }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_x = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@ringbuf = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !25
@event_loss_counter = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !39
@num_cpus = dso_local externally_initialized constant i64 zeroinitializer, section ".rodata", !dbg !56

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(ptr %0) section "s_kprobe_f_1" !dbg !61 {
entry:
  %key13 = alloca i32, align 4
  %helper_error_t8 = alloca %helper_error_t, align 8
  %key = alloca i32, align 4
  %helper_error_t = alloca %helper_error_t, align 8
  %initial_value = alloca i64, align 8
  %lookup_elem_val = alloca i64, align 8
  %tuple = alloca %int64_int64__tuple_t, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %tuple)
  call void @llvm.memset.p0.i64(ptr align 1 %tuple, i8 0, i64 16, i1 false)
  %1 = getelementptr %int64_int64__tuple_t, ptr %tuple, i32 0, i32 0
  store i64 1, ptr %1, align 8
  %2 = getelementptr %int64_int64__tuple_t, ptr %tuple, i32 0, i32 1
  store i64 2, ptr %2, align 8
  %lookup_elem = call ptr inttoptr (i64 1 to ptr)(ptr @AT_x, ptr %tuple)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_elem_val)
  %map_lookup_cond = icmp ne ptr %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  %3 = load i64, ptr %lookup_elem, align 8
  %4 = add i64 %3, 1
  store i64 %4, ptr %lookup_elem, align 8
  br label %lookup_merge

lookup_failure:                                   ; preds = %entry
  call void @llvm.lifetime.start.p0(i64 -1, ptr %initial_value)
  store i64 1, ptr %initial_value, align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %tuple, ptr %initial_value, i64 1)
  %5 = trunc i64 %update_elem to i32
  %6 = icmp sge i32 %5, 0
  br i1 %6, label %helper_merge, label %helper_failure

lookup_merge:                                     ; preds = %helper_merge, %lookup_success
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_elem_val)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %tuple)
  %for_each_map_elem = call i64 inttoptr (i64 164 to ptr)(ptr @AT_x, ptr @map_for_each_cb, ptr null, i64 0)
  %7 = trunc i64 %for_each_map_elem to i32
  %8 = icmp sge i32 %7, 0
  br i1 %8, label %helper_merge7, label %helper_failure6

helper_failure:                                   ; preds = %lookup_failure
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t)
  %9 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 0
  store i64 30006, ptr %9, align 8
  %10 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 1
  store i64 0, ptr %10, align 8
  %11 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 2
  store i32 %5, ptr %11, align 4
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
  %12 = atomicrmw add ptr %lookup_elem1, i64 1 seq_cst, align 8
  br label %lookup_merge4

lookup_failure3:                                  ; preds = %event_loss_counter
  br label %lookup_merge4

lookup_merge4:                                    ; preds = %lookup_failure3, %lookup_success2
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key)
  br label %counter_merge

helper_failure6:                                  ; preds = %lookup_merge
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t8)
  %13 = getelementptr %helper_error_t, ptr %helper_error_t8, i64 0, i32 0
  store i64 30006, ptr %13, align 8
  %14 = getelementptr %helper_error_t, ptr %helper_error_t8, i64 0, i32 1
  store i64 2, ptr %14, align 8
  %15 = getelementptr %helper_error_t, ptr %helper_error_t8, i64 0, i32 2
  store i32 %7, ptr %15, align 4
  %ringbuf_output9 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t8, i64 20, i64 0)
  %ringbuf_loss12 = icmp slt i64 %ringbuf_output9, 0
  br i1 %ringbuf_loss12, label %event_loss_counter10, label %counter_merge11

helper_merge7:                                    ; preds = %counter_merge11, %lookup_merge
  ret i64 0

event_loss_counter10:                             ; preds = %helper_failure6
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key13)
  store i32 0, ptr %key13, align 4
  %lookup_elem14 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key13)
  %map_lookup_cond18 = icmp ne ptr %lookup_elem14, null
  br i1 %map_lookup_cond18, label %lookup_success15, label %lookup_failure16

counter_merge11:                                  ; preds = %lookup_merge17, %helper_failure6
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t8)
  br label %helper_merge7

lookup_success15:                                 ; preds = %event_loss_counter10
  %16 = atomicrmw add ptr %lookup_elem14, i64 1 seq_cst, align 8
  br label %lookup_merge17

lookup_failure16:                                 ; preds = %event_loss_counter10
  br label %lookup_merge17

lookup_merge17:                                   ; preds = %lookup_failure16, %lookup_success15
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key13)
  br label %counter_merge11
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

define internal i64 @map_for_each_cb(ptr %0, ptr %1, ptr %2, ptr %3) section ".text" !dbg !68 {
  %"$res" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$res")
  store i64 0, ptr %"$res", align 8
  %"$kv" = alloca %"(int64,int64)_count_t__tuple_t", align 8
  %key = alloca i32, align 4
  %helper_error_t = alloca %helper_error_t, align 8
  %val_2 = alloca i64, align 8
  %val_1 = alloca i64, align 8
  %i = alloca i32, align 4
  call void @llvm.lifetime.start.p0(i64 -1, ptr %i)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %val_1)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %val_2)
  store i32 0, ptr %i, align 4
  store i64 0, ptr %val_1, align 8
  store i64 0, ptr %val_2, align 8
  br label %while_cond

while_cond:                                       ; preds = %lookup_success, %4
  %5 = load i32, ptr @num_cpus, align 4
  %6 = load i32, ptr %i, align 4
  %num_cpu.cmp = icmp ult i32 %6, %5
  br i1 %num_cpu.cmp, label %while_body, label %while_end

while_body:                                       ; preds = %while_cond
  %7 = load i32, ptr %i, align 4
  %lookup_percpu_elem = call ptr inttoptr (i64 195 to ptr)(ptr @AT_x, ptr %1, i32 %7)
  %map_lookup_cond = icmp ne ptr %lookup_percpu_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

while_end:                                        ; preds = %error_failure, %counter_merge, %while_cond
  call void @llvm.lifetime.end.p0(i64 -1, ptr %i)
  %8 = load i64, ptr %val_1, align 8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %val_1)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %val_2)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$kv")
  call void @llvm.memset.p0.i64(ptr align 1 %"$kv", i8 0, i64 24, i1 false)
  %9 = getelementptr %"(int64,int64)_count_t__tuple_t", ptr %"$kv", i32 0, i32 0
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %9, ptr align 1 %1, i64 16, i1 false)
  %10 = getelementptr %"(int64,int64)_count_t__tuple_t", ptr %"$kv", i32 0, i32 1
  store i64 %8, ptr %10, align 8
  %11 = getelementptr %"(int64,int64)_count_t__tuple_t", ptr %"$kv", i32 0, i32 1
  %12 = load i64, ptr %11, align 8
  store i64 %12, ptr %"$res", align 8
  ret i64 0

lookup_success:                                   ; preds = %while_body
  %13 = load i64, ptr %val_1, align 8
  %14 = load i64, ptr %lookup_percpu_elem, align 8
  %15 = add i64 %14, %13
  store i64 %15, ptr %val_1, align 8
  %16 = load i32, ptr %i, align 4
  %17 = add i32 %16, 1
  store i32 %17, ptr %i, align 4
  br label %while_cond

lookup_failure:                                   ; preds = %while_body
  %18 = load i32, ptr %i, align 4
  %error_lookup_cond = icmp eq i32 %18, 0
  br i1 %error_lookup_cond, label %error_success, label %error_failure

error_success:                                    ; preds = %lookup_failure
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t)
  %19 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 0
  store i64 30006, ptr %19, align 8
  %20 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 1
  store i64 1, ptr %20, align 8
  %21 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 2
  store i32 0, ptr %21, align 4
  %ringbuf_output = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t, i64 20, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

error_failure:                                    ; preds = %lookup_failure
  %22 = load i32, ptr %i, align 4
  br label %while_end

event_loss_counter:                               ; preds = %error_success
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key)
  store i32 0, ptr %key, align 4
  %lookup_elem = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key)
  %map_lookup_cond3 = icmp ne ptr %lookup_elem, null
  br i1 %map_lookup_cond3, label %lookup_success1, label %lookup_failure2

counter_merge:                                    ; preds = %lookup_merge, %error_success
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t)
  br label %while_end

lookup_success1:                                  ; preds = %event_loss_counter
  %23 = atomicrmw add ptr %lookup_elem, i64 1 seq_cst, align 8
  br label %lookup_merge

lookup_failure2:                                  ; preds = %event_loss_counter
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure2, %lookup_success1
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key)
  br label %counter_merge
}

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: readwrite)
declare void @llvm.memcpy.p0.p0.i64(ptr noalias nocapture writeonly %0, ptr noalias nocapture readonly %1, i64 %2, i1 immarg %3) #3

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #2 = { nocallback nofree nounwind willreturn memory(argmem: write) }
attributes #3 = { nocallback nofree nounwind willreturn memory(argmem: readwrite) }

!llvm.dbg.cu = !{!58}
!llvm.module.flags = !{!60}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "AT_x", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !4)
!4 = !{!5, !11, !16, !23}
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
!18 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !19)
!19 = !{!20, !22}
!20 = !DIDerivedType(tag: DW_TAG_member, scope: !2, file: !2, baseType: !21, size: 64)
!21 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!22 = !DIDerivedType(tag: DW_TAG_member, scope: !2, file: !2, baseType: !21, size: 64, offset: 64)
!23 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !24, size: 64, offset: 192)
!24 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !21, size: 64)
!25 = !DIGlobalVariableExpression(var: !26, expr: !DIExpression())
!26 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !27, isLocal: false, isDefinition: true)
!27 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !28)
!28 = !{!29, !34}
!29 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !30, size: 64)
!30 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !31, size: 64)
!31 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !32)
!32 = !{!33}
!33 = !DISubrange(count: 27, lowerBound: 0)
!34 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !35, size: 64, offset: 64)
!35 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !36, size: 64)
!36 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !37)
!37 = !{!38}
!38 = !DISubrange(count: 262144, lowerBound: 0)
!39 = !DIGlobalVariableExpression(var: !40, expr: !DIExpression())
!40 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !41, isLocal: false, isDefinition: true)
!41 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !42)
!42 = !{!43, !48, !53, !23}
!43 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !44, size: 64)
!44 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !45, size: 64)
!45 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !46)
!46 = !{!47}
!47 = !DISubrange(count: 2, lowerBound: 0)
!48 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !49, size: 64, offset: 64)
!49 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !50, size: 64)
!50 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 32, elements: !51)
!51 = !{!52}
!52 = !DISubrange(count: 1, lowerBound: 0)
!53 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !54, size: 64, offset: 128)
!54 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !55, size: 64)
!55 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!56 = !DIGlobalVariableExpression(var: !57, expr: !DIExpression())
!57 = distinct !DIGlobalVariable(name: "num_cpus", linkageName: "global", scope: !2, file: !2, type: !21, isLocal: false, isDefinition: true)
!58 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !59)
!59 = !{!0, !25, !39, !56}
!60 = !{i32 2, !"Debug Info Version", i32 3}
!61 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !62, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !58, retainedNodes: !66)
!62 = !DISubroutineType(types: !63)
!63 = !{!21, !64}
!64 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !65, size: 64)
!65 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!66 = !{!67}
!67 = !DILocalVariable(name: "ctx", arg: 1, scope: !61, file: !2, type: !64)
!68 = distinct !DISubprogram(name: "map_for_each_cb", linkageName: "map_for_each_cb", scope: !2, file: !2, type: !69, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !58, retainedNodes: !71)
!69 = !DISubroutineType(types: !70)
!70 = !{!21, !64, !64, !64, !64}
!71 = !{!72, !73, !74, !75}
!72 = !DILocalVariable(name: "map", arg: 1, scope: !68, file: !2, type: !64)
!73 = !DILocalVariable(name: "key", arg: 2, scope: !68, file: !2, type: !64)
!74 = !DILocalVariable(name: "value", arg: 3, scope: !68, file: !2, type: !64)
!75 = !DILocalVariable(name: "ctx", arg: 4, scope: !68, file: !2, type: !64)
