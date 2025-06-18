; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr, ptr, ptr }
%"struct map_t.1" = type { ptr, ptr, ptr, ptr }
%"struct map_t.2" = type { ptr, ptr, ptr, ptr }
%"struct map_t.3" = type { ptr, ptr }
%helper_error_t = type <{ i64, i64, i32 }>
%kstack_key = type { i64, i64 }
%ustack_key = type { i64, i64, i32, i32 }

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@AT_x = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !7
@AT_y = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !26
@stack_bpftrace_127 = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !35
@stack_scratch = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !55
@ringbuf = dso_local global %"struct map_t.3" zeroinitializer, section ".maps", !dbg !67
@__bt__event_loss_counter = dso_local externally_initialized global i64 0, section ".data.event_loss_counter", !dbg !81

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

; Function Attrs: nounwind
define i64 @kprobe_f_1(ptr %0) #0 section "s_kprobe_f_1" !dbg !87 {
entry:
  %helper_error_t47 = alloca %helper_error_t, align 8
  %"@y_key" = alloca i64, align 8
  %helper_error_t39 = alloca %helper_error_t, align 8
  %helper_error_t30 = alloca %helper_error_t, align 8
  %lookup_stack_scratch_key19 = alloca i32, align 4
  %stack_key16 = alloca %kstack_key, align 8
  %helper_error_t11 = alloca %helper_error_t, align 8
  %"@x_key" = alloca i64, align 8
  %helper_error_t3 = alloca %helper_error_t, align 8
  %helper_error_t = alloca %helper_error_t, align 8
  %lookup_stack_scratch_key = alloca i32, align 4
  %stack_key = alloca %ustack_key, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %stack_key)
  call void @llvm.memset.p0.i64(ptr align 1 %stack_key, i8 0, i64 24, i1 false)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_stack_scratch_key)
  store i32 0, ptr %lookup_stack_scratch_key, align 4
  %lookup_stack_scratch_map = call ptr inttoptr (i64 1 to ptr)(ptr @stack_scratch, ptr %lookup_stack_scratch_key)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_stack_scratch_key)
  %lookup_stack_scratch_cond = icmp ne ptr %lookup_stack_scratch_map, null
  br i1 %lookup_stack_scratch_cond, label %lookup_stack_scratch_merge, label %lookup_stack_scratch_failure

stack_scratch_failure:                            ; preds = %lookup_stack_scratch_failure
  br label %merge_block

merge_block:                                      ; preds = %stack_scratch_failure, %helper_merge2, %get_stack_fail
  %1 = getelementptr %ustack_key, ptr %stack_key, i64 0, i32 2
  %get_pid_tgid = call i64 inttoptr (i64 14 to ptr)()
  %2 = lshr i64 %get_pid_tgid, 32
  %pid = trunc i64 %2 to i32
  store i32 %pid, ptr %1, align 4
  %3 = getelementptr %ustack_key, ptr %stack_key, i64 0, i32 3
  store i32 0, ptr %3, align 4
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key")
  store i64 0, ptr %"@x_key", align 8
  %update_elem8 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %"@x_key", ptr %stack_key, i64 0)
  %4 = trunc i64 %update_elem8 to i32
  %5 = icmp sge i32 %4, 0
  br i1 %5, label %helper_merge10, label %helper_failure9

lookup_stack_scratch_failure:                     ; preds = %entry
  br label %stack_scratch_failure

lookup_stack_scratch_merge:                       ; preds = %entry
  %probe_read_kernel = call i64 inttoptr (i64 113 to ptr)(ptr %lookup_stack_scratch_map, i32 1016, ptr null)
  %get_stack = call i64 inttoptr (i64 67 to ptr)(ptr %0, ptr %lookup_stack_scratch_map, i32 1016, i64 256)
  %6 = trunc i64 %get_stack to i32
  %7 = icmp sge i32 %6, 0
  br i1 %7, label %helper_merge, label %helper_failure

get_stack_success:                                ; preds = %helper_merge
  %8 = udiv i64 %get_stack, 8
  %9 = getelementptr %ustack_key, ptr %stack_key, i64 0, i32 1
  store i64 %8, ptr %9, align 8
  %10 = trunc i64 %8 to i8
  %murmur_hash_2 = call i64 @murmur_hash_2(ptr %lookup_stack_scratch_map, i8 %10, i64 1)
  %11 = getelementptr %ustack_key, ptr %stack_key, i64 0, i32 0
  store i64 %murmur_hash_2, ptr %11, align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @stack_bpftrace_127, ptr %stack_key, ptr %lookup_stack_scratch_map, i64 0)
  %12 = trunc i64 %update_elem to i32
  %13 = icmp sge i32 %12, 0
  br i1 %13, label %helper_merge2, label %helper_failure1

get_stack_fail:                                   ; preds = %helper_merge
  br label %merge_block

helper_failure:                                   ; preds = %lookup_stack_scratch_merge
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t)
  %14 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 0
  store i64 30006, ptr %14, align 8
  %15 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 1
  store i64 0, ptr %15, align 8
  %16 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 2
  store i32 %6, ptr %16, align 4
  %ringbuf_output = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t, i64 20, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

helper_merge:                                     ; preds = %counter_merge, %lookup_stack_scratch_merge
  %17 = icmp sge i64 %get_stack, 0
  br i1 %17, label %get_stack_success, label %get_stack_fail

event_loss_counter:                               ; preds = %helper_failure
  %18 = atomicrmw add ptr @__bt__event_loss_counter, i64 1 seq_cst, align 8
  br label %counter_merge

counter_merge:                                    ; preds = %event_loss_counter, %helper_failure
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t)
  br label %helper_merge

helper_failure1:                                  ; preds = %get_stack_success
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t3)
  %19 = getelementptr %helper_error_t, ptr %helper_error_t3, i64 0, i32 0
  store i64 30006, ptr %19, align 8
  %20 = getelementptr %helper_error_t, ptr %helper_error_t3, i64 0, i32 1
  store i64 1, ptr %20, align 8
  %21 = getelementptr %helper_error_t, ptr %helper_error_t3, i64 0, i32 2
  store i32 %12, ptr %21, align 4
  %ringbuf_output4 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t3, i64 20, i64 0)
  %ringbuf_loss7 = icmp slt i64 %ringbuf_output4, 0
  br i1 %ringbuf_loss7, label %event_loss_counter5, label %counter_merge6

helper_merge2:                                    ; preds = %counter_merge6, %get_stack_success
  br label %merge_block

event_loss_counter5:                              ; preds = %helper_failure1
  %22 = atomicrmw add ptr @__bt__event_loss_counter, i64 1 seq_cst, align 8
  br label %counter_merge6

counter_merge6:                                   ; preds = %event_loss_counter5, %helper_failure1
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t3)
  br label %helper_merge2

helper_failure9:                                  ; preds = %merge_block
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t11)
  %23 = getelementptr %helper_error_t, ptr %helper_error_t11, i64 0, i32 0
  store i64 30006, ptr %23, align 8
  %24 = getelementptr %helper_error_t, ptr %helper_error_t11, i64 0, i32 1
  store i64 2, ptr %24, align 8
  %25 = getelementptr %helper_error_t, ptr %helper_error_t11, i64 0, i32 2
  store i32 %4, ptr %25, align 4
  %ringbuf_output12 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t11, i64 20, i64 0)
  %ringbuf_loss15 = icmp slt i64 %ringbuf_output12, 0
  br i1 %ringbuf_loss15, label %event_loss_counter13, label %counter_merge14

helper_merge10:                                   ; preds = %counter_merge14, %merge_block
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %stack_key16)
  call void @llvm.memset.p0.i64(ptr align 1 %stack_key16, i8 0, i64 16, i1 false)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_stack_scratch_key19)
  store i32 0, ptr %lookup_stack_scratch_key19, align 4
  %lookup_stack_scratch_map20 = call ptr inttoptr (i64 1 to ptr)(ptr @stack_scratch, ptr %lookup_stack_scratch_key19)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_stack_scratch_key19)
  %lookup_stack_scratch_cond23 = icmp ne ptr %lookup_stack_scratch_map20, null
  br i1 %lookup_stack_scratch_cond23, label %lookup_stack_scratch_merge22, label %lookup_stack_scratch_failure21

event_loss_counter13:                             ; preds = %helper_failure9
  %26 = atomicrmw add ptr @__bt__event_loss_counter, i64 1 seq_cst, align 8
  br label %counter_merge14

counter_merge14:                                  ; preds = %event_loss_counter13, %helper_failure9
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t11)
  br label %helper_merge10

stack_scratch_failure17:                          ; preds = %lookup_stack_scratch_failure21
  br label %merge_block18

merge_block18:                                    ; preds = %stack_scratch_failure17, %helper_merge38, %get_stack_fail26
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@y_key")
  store i64 0, ptr %"@y_key", align 8
  %update_elem44 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_y, ptr %"@y_key", ptr %stack_key16, i64 0)
  %27 = trunc i64 %update_elem44 to i32
  %28 = icmp sge i32 %27, 0
  br i1 %28, label %helper_merge46, label %helper_failure45

lookup_stack_scratch_failure21:                   ; preds = %helper_merge10
  br label %stack_scratch_failure17

lookup_stack_scratch_merge22:                     ; preds = %helper_merge10
  %probe_read_kernel24 = call i64 inttoptr (i64 113 to ptr)(ptr %lookup_stack_scratch_map20, i32 1016, ptr null)
  %get_stack27 = call i64 inttoptr (i64 67 to ptr)(ptr %0, ptr %lookup_stack_scratch_map20, i32 1016, i64 0)
  %29 = trunc i64 %get_stack27 to i32
  %30 = icmp sge i32 %29, 0
  br i1 %30, label %helper_merge29, label %helper_failure28

get_stack_success25:                              ; preds = %helper_merge29
  %31 = udiv i64 %get_stack27, 8
  %32 = getelementptr %kstack_key, ptr %stack_key16, i64 0, i32 1
  store i64 %31, ptr %32, align 8
  %33 = trunc i64 %31 to i8
  %murmur_hash_235 = call i64 @murmur_hash_2(ptr %lookup_stack_scratch_map20, i8 %33, i64 1)
  %34 = getelementptr %kstack_key, ptr %stack_key16, i64 0, i32 0
  store i64 %murmur_hash_235, ptr %34, align 8
  %update_elem36 = call i64 inttoptr (i64 2 to ptr)(ptr @stack_bpftrace_127, ptr %stack_key16, ptr %lookup_stack_scratch_map20, i64 0)
  %35 = trunc i64 %update_elem36 to i32
  %36 = icmp sge i32 %35, 0
  br i1 %36, label %helper_merge38, label %helper_failure37

get_stack_fail26:                                 ; preds = %helper_merge29
  br label %merge_block18

helper_failure28:                                 ; preds = %lookup_stack_scratch_merge22
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t30)
  %37 = getelementptr %helper_error_t, ptr %helper_error_t30, i64 0, i32 0
  store i64 30006, ptr %37, align 8
  %38 = getelementptr %helper_error_t, ptr %helper_error_t30, i64 0, i32 1
  store i64 3, ptr %38, align 8
  %39 = getelementptr %helper_error_t, ptr %helper_error_t30, i64 0, i32 2
  store i32 %29, ptr %39, align 4
  %ringbuf_output31 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t30, i64 20, i64 0)
  %ringbuf_loss34 = icmp slt i64 %ringbuf_output31, 0
  br i1 %ringbuf_loss34, label %event_loss_counter32, label %counter_merge33

helper_merge29:                                   ; preds = %counter_merge33, %lookup_stack_scratch_merge22
  %40 = icmp sge i64 %get_stack27, 0
  br i1 %40, label %get_stack_success25, label %get_stack_fail26

event_loss_counter32:                             ; preds = %helper_failure28
  %41 = atomicrmw add ptr @__bt__event_loss_counter, i64 1 seq_cst, align 8
  br label %counter_merge33

counter_merge33:                                  ; preds = %event_loss_counter32, %helper_failure28
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t30)
  br label %helper_merge29

helper_failure37:                                 ; preds = %get_stack_success25
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t39)
  %42 = getelementptr %helper_error_t, ptr %helper_error_t39, i64 0, i32 0
  store i64 30006, ptr %42, align 8
  %43 = getelementptr %helper_error_t, ptr %helper_error_t39, i64 0, i32 1
  store i64 4, ptr %43, align 8
  %44 = getelementptr %helper_error_t, ptr %helper_error_t39, i64 0, i32 2
  store i32 %35, ptr %44, align 4
  %ringbuf_output40 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t39, i64 20, i64 0)
  %ringbuf_loss43 = icmp slt i64 %ringbuf_output40, 0
  br i1 %ringbuf_loss43, label %event_loss_counter41, label %counter_merge42

helper_merge38:                                   ; preds = %counter_merge42, %get_stack_success25
  br label %merge_block18

event_loss_counter41:                             ; preds = %helper_failure37
  %45 = atomicrmw add ptr @__bt__event_loss_counter, i64 1 seq_cst, align 8
  br label %counter_merge42

counter_merge42:                                  ; preds = %event_loss_counter41, %helper_failure37
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t39)
  br label %helper_merge38

helper_failure45:                                 ; preds = %merge_block18
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t47)
  %46 = getelementptr %helper_error_t, ptr %helper_error_t47, i64 0, i32 0
  store i64 30006, ptr %46, align 8
  %47 = getelementptr %helper_error_t, ptr %helper_error_t47, i64 0, i32 1
  store i64 5, ptr %47, align 8
  %48 = getelementptr %helper_error_t, ptr %helper_error_t47, i64 0, i32 2
  store i32 %27, ptr %48, align 4
  %ringbuf_output48 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t47, i64 20, i64 0)
  %ringbuf_loss51 = icmp slt i64 %ringbuf_output48, 0
  br i1 %ringbuf_loss51, label %event_loss_counter49, label %counter_merge50

helper_merge46:                                   ; preds = %counter_merge50, %merge_block18
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@y_key")
  ret i64 0

event_loss_counter49:                             ; preds = %helper_failure45
  %49 = atomicrmw add ptr @__bt__event_loss_counter, i64 1 seq_cst, align 8
  br label %counter_merge50

counter_merge50:                                  ; preds = %event_loss_counter49, %helper_failure45
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t47)
  br label %helper_merge46
}

; Function Attrs: alwaysinline nounwind
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

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #3

attributes #0 = { nounwind }
attributes #1 = { alwaysinline nounwind }
attributes #2 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #3 = { nocallback nofree nounwind willreturn memory(argmem: write) }

!llvm.dbg.cu = !{!83}
!llvm.module.flags = !{!85, !86}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "LICENSE", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 32, elements: !5)
!4 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!5 = !{!6}
!6 = !DISubrange(count: 4, lowerBound: 0)
!7 = !DIGlobalVariableExpression(var: !8, expr: !DIExpression())
!8 = distinct !DIGlobalVariable(name: "AT_x", linkageName: "global", scope: !2, file: !2, type: !9, isLocal: false, isDefinition: true)
!9 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !10)
!10 = !{!11, !17, !18, !21}
!11 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !12, size: 64)
!12 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !13, size: 64)
!13 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 32, elements: !15)
!14 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!15 = !{!16}
!16 = !DISubrange(count: 1, lowerBound: 0)
!17 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !12, size: 64, offset: 64)
!18 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !19, size: 64, offset: 128)
!19 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !20, size: 64)
!20 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!21 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !22, size: 64, offset: 192)
!22 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !23, size: 64)
!23 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 192, elements: !24)
!24 = !{!25}
!25 = !DISubrange(count: 24, lowerBound: 0)
!26 = !DIGlobalVariableExpression(var: !27, expr: !DIExpression())
!27 = distinct !DIGlobalVariable(name: "AT_y", linkageName: "global", scope: !2, file: !2, type: !28, isLocal: false, isDefinition: true)
!28 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !29)
!29 = !{!11, !17, !18, !30}
!30 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !31, size: 64, offset: 192)
!31 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !32, size: 64)
!32 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 128, elements: !33)
!33 = !{!34}
!34 = !DISubrange(count: 16, lowerBound: 0)
!35 = !DIGlobalVariableExpression(var: !36, expr: !DIExpression())
!36 = distinct !DIGlobalVariable(name: "stack_bpftrace_127", linkageName: "global", scope: !2, file: !2, type: !37, isLocal: false, isDefinition: true)
!37 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !38)
!38 = !{!39, !44, !49, !50}
!39 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !40, size: 64)
!40 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !41, size: 64)
!41 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 288, elements: !42)
!42 = !{!43}
!43 = !DISubrange(count: 9, lowerBound: 0)
!44 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !45, size: 64, offset: 64)
!45 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !46, size: 64)
!46 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 4194304, elements: !47)
!47 = !{!48}
!48 = !DISubrange(count: 131072, lowerBound: 0)
!49 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !31, size: 64, offset: 128)
!50 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !51, size: 64, offset: 192)
!51 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !52, size: 64)
!52 = !DICompositeType(tag: DW_TAG_array_type, baseType: !20, size: 8128, elements: !53)
!53 = !{!54}
!54 = !DISubrange(count: 127, lowerBound: 0)
!55 = !DIGlobalVariableExpression(var: !56, expr: !DIExpression())
!56 = distinct !DIGlobalVariable(name: "stack_scratch", linkageName: "global", scope: !2, file: !2, type: !57, isLocal: false, isDefinition: true)
!57 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !58)
!58 = !{!59, !17, !64, !50}
!59 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !60, size: 64)
!60 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !61, size: 64)
!61 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 192, elements: !62)
!62 = !{!63}
!63 = !DISubrange(count: 6, lowerBound: 0)
!64 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !65, size: 64, offset: 128)
!65 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !66, size: 64)
!66 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!67 = !DIGlobalVariableExpression(var: !68, expr: !DIExpression())
!68 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !69, isLocal: false, isDefinition: true)
!69 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !70)
!70 = !{!71, !76}
!71 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !72, size: 64)
!72 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !73, size: 64)
!73 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 864, elements: !74)
!74 = !{!75}
!75 = !DISubrange(count: 27, lowerBound: 0)
!76 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !77, size: 64, offset: 64)
!77 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !78, size: 64)
!78 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 8388608, elements: !79)
!79 = !{!80}
!80 = !DISubrange(count: 262144, lowerBound: 0)
!81 = !DIGlobalVariableExpression(var: !82, expr: !DIExpression())
!82 = distinct !DIGlobalVariable(name: "__bt__event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !20, isLocal: false, isDefinition: true)
!83 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !84)
!84 = !{!0, !7, !26, !35, !55, !67, !81}
!85 = !{i32 2, !"Debug Info Version", i32 3}
!86 = !{i32 7, !"uwtable", i32 0}
!87 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !88, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !83, retainedNodes: !91)
!88 = !DISubroutineType(types: !89)
!89 = !{!20, !90}
!90 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!91 = !{!92}
!92 = !DILocalVariable(name: "ctx", arg: 1, scope: !87, file: !2, type: !90)
