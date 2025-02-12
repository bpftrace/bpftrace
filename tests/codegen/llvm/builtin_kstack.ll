; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr, ptr, ptr }
%"struct map_t.1" = type { ptr, ptr, ptr, ptr }
%"struct map_t.2" = type { ptr, ptr }
%"struct map_t.3" = type { ptr, ptr, ptr, ptr }
%helper_error_t = type <{ i64, i64, i32 }>
%kstack_key = type { i64, i32 }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_x = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@stack_bpftrace_127 = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !21
@stack_scratch = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !41
@ringbuf = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !53
@event_loss_counter = dso_local global %"struct map_t.3" zeroinitializer, section ".maps", !dbg !67

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(ptr %0) section "s_kprobe_f_1" !dbg !80 {
entry:
  %key22 = alloca i32, align 4
  %helper_error_t17 = alloca %helper_error_t, align 8
  %"@x_key" = alloca i64, align 8
  %key8 = alloca i32, align 4
  %helper_error_t3 = alloca %helper_error_t, align 8
  %key = alloca i32, align 4
  %helper_error_t = alloca %helper_error_t, align 8
  %lookup_stack_scratch_key = alloca i32, align 4
  %stack_key = alloca %kstack_key, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %stack_key)
  %1 = getelementptr %kstack_key, ptr %stack_key, i64 0, i32 0
  store i64 0, ptr %1, align 8
  %2 = getelementptr %kstack_key, ptr %stack_key, i64 0, i32 1
  store i32 0, ptr %2, align 4
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_stack_scratch_key)
  store i32 0, ptr %lookup_stack_scratch_key, align 4
  %lookup_stack_scratch_map = call ptr inttoptr (i64 1 to ptr)(ptr @stack_scratch, ptr %lookup_stack_scratch_key)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_stack_scratch_key)
  %lookup_stack_scratch_cond = icmp ne ptr %lookup_stack_scratch_map, null
  br i1 %lookup_stack_scratch_cond, label %lookup_stack_scratch_merge, label %lookup_stack_scratch_failure

stack_scratch_failure:                            ; preds = %lookup_stack_scratch_failure
  br label %merge_block

merge_block:                                      ; preds = %stack_scratch_failure, %helper_merge2, %get_stack_fail
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key")
  store i64 0, ptr %"@x_key", align 8
  %update_elem14 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %"@x_key", ptr %stack_key, i64 0)
  %3 = trunc i64 %update_elem14 to i32
  %4 = icmp sge i32 %3, 0
  br i1 %4, label %helper_merge16, label %helper_failure15

lookup_stack_scratch_failure:                     ; preds = %entry
  br label %stack_scratch_failure

lookup_stack_scratch_merge:                       ; preds = %entry
  %probe_read_kernel = call i64 inttoptr (i64 113 to ptr)(ptr %lookup_stack_scratch_map, i32 1016, ptr null)
  %get_stack = call i32 inttoptr (i64 67 to ptr)(ptr %0, ptr %lookup_stack_scratch_map, i32 1016, i64 0)
  %5 = icmp sge i32 %get_stack, 0
  br i1 %5, label %helper_merge, label %helper_failure

get_stack_success:                                ; preds = %helper_merge
  %6 = udiv i32 %get_stack, 8
  %7 = getelementptr %kstack_key, ptr %stack_key, i64 0, i32 1
  store i32 %6, ptr %7, align 4
  %8 = trunc i32 %6 to i8
  %murmur_hash_2 = call i64 @murmur_hash_2(ptr %lookup_stack_scratch_map, i8 %8, i64 1)
  %9 = getelementptr %kstack_key, ptr %stack_key, i64 0, i32 0
  store i64 %murmur_hash_2, ptr %9, align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @stack_bpftrace_127, ptr %stack_key, ptr %lookup_stack_scratch_map, i64 0)
  %10 = trunc i64 %update_elem to i32
  %11 = icmp sge i32 %10, 0
  br i1 %11, label %helper_merge2, label %helper_failure1

get_stack_fail:                                   ; preds = %helper_merge
  br label %merge_block

helper_failure:                                   ; preds = %lookup_stack_scratch_merge
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t)
  %12 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 0
  store i64 30006, ptr %12, align 8
  %13 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 1
  store i64 0, ptr %13, align 8
  %14 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 2
  store i32 %get_stack, ptr %14, align 4
  %ringbuf_output = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t, i64 20, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

helper_merge:                                     ; preds = %counter_merge, %lookup_stack_scratch_merge
  %15 = icmp sge i32 %get_stack, 0
  br i1 %15, label %get_stack_success, label %get_stack_fail

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

helper_failure1:                                  ; preds = %get_stack_success
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t3)
  %17 = getelementptr %helper_error_t, ptr %helper_error_t3, i64 0, i32 0
  store i64 30006, ptr %17, align 8
  %18 = getelementptr %helper_error_t, ptr %helper_error_t3, i64 0, i32 1
  store i64 1, ptr %18, align 8
  %19 = getelementptr %helper_error_t, ptr %helper_error_t3, i64 0, i32 2
  store i32 %10, ptr %19, align 4
  %ringbuf_output4 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t3, i64 20, i64 0)
  %ringbuf_loss7 = icmp slt i64 %ringbuf_output4, 0
  br i1 %ringbuf_loss7, label %event_loss_counter5, label %counter_merge6

helper_merge2:                                    ; preds = %counter_merge6, %get_stack_success
  br label %merge_block

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
  %20 = atomicrmw add ptr %lookup_elem9, i64 1 seq_cst, align 8
  br label %lookup_merge12

lookup_failure11:                                 ; preds = %event_loss_counter5
  br label %lookup_merge12

lookup_merge12:                                   ; preds = %lookup_failure11, %lookup_success10
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key8)
  br label %counter_merge6

helper_failure15:                                 ; preds = %merge_block
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t17)
  %21 = getelementptr %helper_error_t, ptr %helper_error_t17, i64 0, i32 0
  store i64 30006, ptr %21, align 8
  %22 = getelementptr %helper_error_t, ptr %helper_error_t17, i64 0, i32 1
  store i64 2, ptr %22, align 8
  %23 = getelementptr %helper_error_t, ptr %helper_error_t17, i64 0, i32 2
  store i32 %3, ptr %23, align 4
  %ringbuf_output18 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t17, i64 20, i64 0)
  %ringbuf_loss21 = icmp slt i64 %ringbuf_output18, 0
  br i1 %ringbuf_loss21, label %event_loss_counter19, label %counter_merge20

helper_merge16:                                   ; preds = %counter_merge20, %merge_block
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key")
  ret i64 0

event_loss_counter19:                             ; preds = %helper_failure15
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key22)
  store i32 0, ptr %key22, align 4
  %lookup_elem23 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key22)
  %map_lookup_cond27 = icmp ne ptr %lookup_elem23, null
  br i1 %map_lookup_cond27, label %lookup_success24, label %lookup_failure25

counter_merge20:                                  ; preds = %lookup_merge26, %helper_failure15
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t17)
  br label %helper_merge16

lookup_success24:                                 ; preds = %event_loss_counter19
  %24 = atomicrmw add ptr %lookup_elem23, i64 1 seq_cst, align 8
  br label %lookup_merge26

lookup_failure25:                                 ; preds = %event_loss_counter19
  br label %lookup_merge26

lookup_merge26:                                   ; preds = %lookup_failure25, %lookup_success24
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key22)
  br label %counter_merge20
}

; Function Attrs: alwaysinline
define internal i64 @murmur_hash_2(ptr %0, i8 %1, i64 %2) #1 section "helpers" {
entry:
  %k = alloca i64, align 8
  %i = alloca i8, align 1
  %id = alloca i64, align 8
  %seed_addr = alloca i64, align 8
  %nr_stack_frames_addr = alloca i8, align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %nr_stack_frames_addr)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %seed_addr)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %id)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %i)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %k)
  store i8 %1, ptr %nr_stack_frames_addr, align 1
  store i64 %2, ptr %seed_addr, align 8
  %3 = load i8, ptr %nr_stack_frames_addr, align 1
  %4 = zext i8 %3 to i64
  %5 = mul i64 %4, -4132994306676758123
  %6 = load i64, ptr %seed_addr, align 8
  %7 = xor i64 %6, %5
  store i64 %7, ptr %id, align 8
  store i8 0, ptr %i, align 1
  br label %while_cond

while_cond:                                       ; preds = %while_body, %entry
  %8 = load i8, ptr %nr_stack_frames_addr, align 1
  %9 = load i8, ptr %i, align 1
  %length.cmp = icmp ult i8 %9, %8
  br i1 %length.cmp, label %while_body, label %while_end

while_body:                                       ; preds = %while_cond
  %10 = load i8, ptr %i, align 1
  %11 = getelementptr i64, ptr %0, i8 %10
  %12 = load i64, ptr %11, align 8
  store i64 %12, ptr %k, align 8
  %13 = load i64, ptr %k, align 8
  %14 = mul i64 %13, -4132994306676758123
  store i64 %14, ptr %k, align 8
  %15 = load i64, ptr %k, align 8
  %16 = lshr i64 %15, 47
  %17 = load i64, ptr %k, align 8
  %18 = xor i64 %17, %16
  store i64 %18, ptr %k, align 8
  %19 = load i64, ptr %k, align 8
  %20 = mul i64 %19, -4132994306676758123
  store i64 %20, ptr %k, align 8
  %21 = load i64, ptr %k, align 8
  %22 = load i64, ptr %id, align 8
  %23 = xor i64 %22, %21
  store i64 %23, ptr %id, align 8
  %24 = load i64, ptr %id, align 8
  %25 = mul i64 %24, -4132994306676758123
  store i64 %25, ptr %id, align 8
  %26 = load i8, ptr %i, align 1
  %27 = add i8 %26, 1
  store i8 %27, ptr %i, align 1
  br label %while_cond

while_end:                                        ; preds = %while_cond
  call void @llvm.lifetime.end.p0(i64 -1, ptr %nr_stack_frames_addr)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %seed_addr)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %i)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %k)
  %28 = load i64, ptr %id, align 8
  %zero_cond = icmp eq i64 %28, 0
  br i1 %zero_cond, label %if_zero, label %if_end

if_zero:                                          ; preds = %while_end
  store i64 1, ptr %id, align 8
  br label %if_end

if_end:                                           ; preds = %if_zero, %while_end
  %29 = load i64, ptr %id, align 8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %id)
  ret i64 %29
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #2

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #2

attributes #0 = { nounwind }
attributes #1 = { alwaysinline }
attributes #2 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }

!llvm.dbg.cu = !{!77}
!llvm.module.flags = !{!79}

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
!17 = !DICompositeType(tag: DW_TAG_array_type, baseType: !18, size: 96, elements: !19)
!18 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!19 = !{!20}
!20 = !DISubrange(count: 12, lowerBound: 0)
!21 = !DIGlobalVariableExpression(var: !22, expr: !DIExpression())
!22 = distinct !DIGlobalVariable(name: "stack_bpftrace_127", linkageName: "global", scope: !2, file: !2, type: !23, isLocal: false, isDefinition: true)
!23 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !24)
!24 = !{!25, !30, !35, !36}
!25 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !26, size: 64)
!26 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !27, size: 64)
!27 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 288, elements: !28)
!28 = !{!29}
!29 = !DISubrange(count: 9, lowerBound: 0)
!30 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !31, size: 64, offset: 64)
!31 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !32, size: 64)
!32 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 4194304, elements: !33)
!33 = !{!34}
!34 = !DISubrange(count: 131072, lowerBound: 0)
!35 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !16, size: 64, offset: 128)
!36 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !37, size: 64, offset: 192)
!37 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !38, size: 64)
!38 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 8128, elements: !39)
!39 = !{!40}
!40 = !DISubrange(count: 127, lowerBound: 0)
!41 = !DIGlobalVariableExpression(var: !42, expr: !DIExpression())
!42 = distinct !DIGlobalVariable(name: "stack_scratch", linkageName: "global", scope: !2, file: !2, type: !43, isLocal: false, isDefinition: true)
!43 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !44)
!44 = !{!45, !11, !50, !36}
!45 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !46, size: 64)
!46 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !47, size: 64)
!47 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 192, elements: !48)
!48 = !{!49}
!49 = !DISubrange(count: 6, lowerBound: 0)
!50 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !51, size: 64, offset: 128)
!51 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !52, size: 64)
!52 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!53 = !DIGlobalVariableExpression(var: !54, expr: !DIExpression())
!54 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !55, isLocal: false, isDefinition: true)
!55 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !56)
!56 = !{!57, !62}
!57 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !58, size: 64)
!58 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !59, size: 64)
!59 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !60)
!60 = !{!61}
!61 = !DISubrange(count: 27, lowerBound: 0)
!62 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !63, size: 64, offset: 64)
!63 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !64, size: 64)
!64 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !65)
!65 = !{!66}
!66 = !DISubrange(count: 262144, lowerBound: 0)
!67 = !DIGlobalVariableExpression(var: !68, expr: !DIExpression())
!68 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !69, isLocal: false, isDefinition: true)
!69 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !70)
!70 = !{!71, !11, !50, !76}
!71 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !72, size: 64)
!72 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !73, size: 64)
!73 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !74)
!74 = !{!75}
!75 = !DISubrange(count: 2, lowerBound: 0)
!76 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !13, size: 64, offset: 192)
!77 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !78)
!78 = !{!0, !21, !41, !53, !67}
!79 = !{i32 2, !"Debug Info Version", i32 3}
!80 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !81, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !77, retainedNodes: !84)
!81 = !DISubroutineType(types: !82)
!82 = !{!14, !83}
!83 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !18, size: 64)
!84 = !{!85}
!85 = !DILocalVariable(name: "ctx", arg: 1, scope: !80, file: !2, type: !83)
