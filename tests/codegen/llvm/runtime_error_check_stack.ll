; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr, ptr, ptr }
%"struct map_t.1" = type { ptr, ptr, ptr, ptr }
%"struct map_t.2" = type { ptr, ptr, ptr, ptr }
%"struct map_t.3" = type { ptr, ptr }
%"struct map_t.4" = type { ptr, ptr, ptr, ptr }
%helper_error_t = type <{ i64, i64, i32 }>
%kstack_key = type { i64, i64 }
%ustack_key = type { i64, i64, i32, i32 }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_x = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@AT_y = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !21
@stack_bpftrace_127 = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !30
@stack_scratch = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !54
@ringbuf = dso_local global %"struct map_t.3" zeroinitializer, section ".maps", !dbg !66
@event_loss_counter = dso_local global %"struct map_t.4" zeroinitializer, section ".maps", !dbg !80

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(ptr %0) section "s_kprobe_f_1" !dbg !93 {
entry:
  %key76 = alloca i32, align 4
  %helper_error_t71 = alloca %helper_error_t, align 8
  %"@y_key" = alloca i64, align 8
  %key62 = alloca i32, align 4
  %helper_error_t57 = alloca %helper_error_t, align 8
  %key47 = alloca i32, align 4
  %helper_error_t42 = alloca %helper_error_t, align 8
  %lookup_stack_scratch_key31 = alloca i32, align 4
  %stack_key28 = alloca %kstack_key, align 8
  %key22 = alloca i32, align 4
  %helper_error_t17 = alloca %helper_error_t, align 8
  %"@x_key" = alloca i64, align 8
  %key8 = alloca i32, align 4
  %helper_error_t3 = alloca %helper_error_t, align 8
  %key = alloca i32, align 4
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
  %update_elem14 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %"@x_key", ptr %stack_key, i64 0)
  %4 = trunc i64 %update_elem14 to i32
  %5 = icmp sge i32 %4, 0
  br i1 %5, label %helper_merge16, label %helper_failure15

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
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key)
  store i32 0, ptr %key, align 4
  %lookup_elem = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key)
  %map_lookup_cond = icmp ne ptr %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

counter_merge:                                    ; preds = %lookup_merge, %helper_failure
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t)
  br label %helper_merge

lookup_success:                                   ; preds = %event_loss_counter
  %18 = atomicrmw add ptr %lookup_elem, i64 1 seq_cst, align 8
  br label %lookup_merge

lookup_failure:                                   ; preds = %event_loss_counter
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key)
  br label %counter_merge

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
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key8)
  store i32 0, ptr %key8, align 4
  %lookup_elem9 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key8)
  %map_lookup_cond13 = icmp ne ptr %lookup_elem9, null
  br i1 %map_lookup_cond13, label %lookup_success10, label %lookup_failure11

counter_merge6:                                   ; preds = %lookup_merge12, %helper_failure1
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t3)
  br label %helper_merge2

lookup_success10:                                 ; preds = %event_loss_counter5
  %22 = atomicrmw add ptr %lookup_elem9, i64 1 seq_cst, align 8
  br label %lookup_merge12

lookup_failure11:                                 ; preds = %event_loss_counter5
  br label %lookup_merge12

lookup_merge12:                                   ; preds = %lookup_failure11, %lookup_success10
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key8)
  br label %counter_merge6

helper_failure15:                                 ; preds = %merge_block
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t17)
  %23 = getelementptr %helper_error_t, ptr %helper_error_t17, i64 0, i32 0
  store i64 30006, ptr %23, align 8
  %24 = getelementptr %helper_error_t, ptr %helper_error_t17, i64 0, i32 1
  store i64 2, ptr %24, align 8
  %25 = getelementptr %helper_error_t, ptr %helper_error_t17, i64 0, i32 2
  store i32 %4, ptr %25, align 4
  %ringbuf_output18 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t17, i64 20, i64 0)
  %ringbuf_loss21 = icmp slt i64 %ringbuf_output18, 0
  br i1 %ringbuf_loss21, label %event_loss_counter19, label %counter_merge20

helper_merge16:                                   ; preds = %counter_merge20, %merge_block
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %stack_key28)
  call void @llvm.memset.p0.i64(ptr align 1 %stack_key28, i8 0, i64 16, i1 false)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_stack_scratch_key31)
  store i32 0, ptr %lookup_stack_scratch_key31, align 4
  %lookup_stack_scratch_map32 = call ptr inttoptr (i64 1 to ptr)(ptr @stack_scratch, ptr %lookup_stack_scratch_key31)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_stack_scratch_key31)
  %lookup_stack_scratch_cond35 = icmp ne ptr %lookup_stack_scratch_map32, null
  br i1 %lookup_stack_scratch_cond35, label %lookup_stack_scratch_merge34, label %lookup_stack_scratch_failure33

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
  %26 = atomicrmw add ptr %lookup_elem23, i64 1 seq_cst, align 8
  br label %lookup_merge26

lookup_failure25:                                 ; preds = %event_loss_counter19
  br label %lookup_merge26

lookup_merge26:                                   ; preds = %lookup_failure25, %lookup_success24
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key22)
  br label %counter_merge20

stack_scratch_failure29:                          ; preds = %lookup_stack_scratch_failure33
  br label %merge_block30

merge_block30:                                    ; preds = %stack_scratch_failure29, %helper_merge56, %get_stack_fail38
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@y_key")
  store i64 0, ptr %"@y_key", align 8
  %update_elem68 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_y, ptr %"@y_key", ptr %stack_key28, i64 0)
  %27 = trunc i64 %update_elem68 to i32
  %28 = icmp sge i32 %27, 0
  br i1 %28, label %helper_merge70, label %helper_failure69

lookup_stack_scratch_failure33:                   ; preds = %helper_merge16
  br label %stack_scratch_failure29

lookup_stack_scratch_merge34:                     ; preds = %helper_merge16
  %probe_read_kernel36 = call i64 inttoptr (i64 113 to ptr)(ptr %lookup_stack_scratch_map32, i32 1016, ptr null)
  %get_stack39 = call i64 inttoptr (i64 67 to ptr)(ptr %0, ptr %lookup_stack_scratch_map32, i32 1016, i64 0)
  %29 = trunc i64 %get_stack39 to i32
  %30 = icmp sge i32 %29, 0
  br i1 %30, label %helper_merge41, label %helper_failure40

get_stack_success37:                              ; preds = %helper_merge41
  %31 = udiv i64 %get_stack39, 8
  %32 = getelementptr %kstack_key, ptr %stack_key28, i64 0, i32 1
  store i64 %31, ptr %32, align 8
  %33 = trunc i64 %31 to i8
  %murmur_hash_253 = call i64 @murmur_hash_2(ptr %lookup_stack_scratch_map32, i8 %33, i64 1)
  %34 = getelementptr %kstack_key, ptr %stack_key28, i64 0, i32 0
  store i64 %murmur_hash_253, ptr %34, align 8
  %update_elem54 = call i64 inttoptr (i64 2 to ptr)(ptr @stack_bpftrace_127, ptr %stack_key28, ptr %lookup_stack_scratch_map32, i64 0)
  %35 = trunc i64 %update_elem54 to i32
  %36 = icmp sge i32 %35, 0
  br i1 %36, label %helper_merge56, label %helper_failure55

get_stack_fail38:                                 ; preds = %helper_merge41
  br label %merge_block30

helper_failure40:                                 ; preds = %lookup_stack_scratch_merge34
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t42)
  %37 = getelementptr %helper_error_t, ptr %helper_error_t42, i64 0, i32 0
  store i64 30006, ptr %37, align 8
  %38 = getelementptr %helper_error_t, ptr %helper_error_t42, i64 0, i32 1
  store i64 3, ptr %38, align 8
  %39 = getelementptr %helper_error_t, ptr %helper_error_t42, i64 0, i32 2
  store i32 %29, ptr %39, align 4
  %ringbuf_output43 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t42, i64 20, i64 0)
  %ringbuf_loss46 = icmp slt i64 %ringbuf_output43, 0
  br i1 %ringbuf_loss46, label %event_loss_counter44, label %counter_merge45

helper_merge41:                                   ; preds = %counter_merge45, %lookup_stack_scratch_merge34
  %40 = icmp sge i64 %get_stack39, 0
  br i1 %40, label %get_stack_success37, label %get_stack_fail38

event_loss_counter44:                             ; preds = %helper_failure40
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key47)
  store i32 0, ptr %key47, align 4
  %lookup_elem48 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key47)
  %map_lookup_cond52 = icmp ne ptr %lookup_elem48, null
  br i1 %map_lookup_cond52, label %lookup_success49, label %lookup_failure50

counter_merge45:                                  ; preds = %lookup_merge51, %helper_failure40
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t42)
  br label %helper_merge41

lookup_success49:                                 ; preds = %event_loss_counter44
  %41 = atomicrmw add ptr %lookup_elem48, i64 1 seq_cst, align 8
  br label %lookup_merge51

lookup_failure50:                                 ; preds = %event_loss_counter44
  br label %lookup_merge51

lookup_merge51:                                   ; preds = %lookup_failure50, %lookup_success49
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key47)
  br label %counter_merge45

helper_failure55:                                 ; preds = %get_stack_success37
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t57)
  %42 = getelementptr %helper_error_t, ptr %helper_error_t57, i64 0, i32 0
  store i64 30006, ptr %42, align 8
  %43 = getelementptr %helper_error_t, ptr %helper_error_t57, i64 0, i32 1
  store i64 4, ptr %43, align 8
  %44 = getelementptr %helper_error_t, ptr %helper_error_t57, i64 0, i32 2
  store i32 %35, ptr %44, align 4
  %ringbuf_output58 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t57, i64 20, i64 0)
  %ringbuf_loss61 = icmp slt i64 %ringbuf_output58, 0
  br i1 %ringbuf_loss61, label %event_loss_counter59, label %counter_merge60

helper_merge56:                                   ; preds = %counter_merge60, %get_stack_success37
  br label %merge_block30

event_loss_counter59:                             ; preds = %helper_failure55
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key62)
  store i32 0, ptr %key62, align 4
  %lookup_elem63 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key62)
  %map_lookup_cond67 = icmp ne ptr %lookup_elem63, null
  br i1 %map_lookup_cond67, label %lookup_success64, label %lookup_failure65

counter_merge60:                                  ; preds = %lookup_merge66, %helper_failure55
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t57)
  br label %helper_merge56

lookup_success64:                                 ; preds = %event_loss_counter59
  %45 = atomicrmw add ptr %lookup_elem63, i64 1 seq_cst, align 8
  br label %lookup_merge66

lookup_failure65:                                 ; preds = %event_loss_counter59
  br label %lookup_merge66

lookup_merge66:                                   ; preds = %lookup_failure65, %lookup_success64
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key62)
  br label %counter_merge60

helper_failure69:                                 ; preds = %merge_block30
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t71)
  %46 = getelementptr %helper_error_t, ptr %helper_error_t71, i64 0, i32 0
  store i64 30006, ptr %46, align 8
  %47 = getelementptr %helper_error_t, ptr %helper_error_t71, i64 0, i32 1
  store i64 5, ptr %47, align 8
  %48 = getelementptr %helper_error_t, ptr %helper_error_t71, i64 0, i32 2
  store i32 %27, ptr %48, align 4
  %ringbuf_output72 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t71, i64 20, i64 0)
  %ringbuf_loss75 = icmp slt i64 %ringbuf_output72, 0
  br i1 %ringbuf_loss75, label %event_loss_counter73, label %counter_merge74

helper_merge70:                                   ; preds = %counter_merge74, %merge_block30
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@y_key")
  ret i64 0

event_loss_counter73:                             ; preds = %helper_failure69
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key76)
  store i32 0, ptr %key76, align 4
  %lookup_elem77 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key76)
  %map_lookup_cond81 = icmp ne ptr %lookup_elem77, null
  br i1 %map_lookup_cond81, label %lookup_success78, label %lookup_failure79

counter_merge74:                                  ; preds = %lookup_merge80, %helper_failure69
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t71)
  br label %helper_merge70

lookup_success78:                                 ; preds = %event_loss_counter73
  %49 = atomicrmw add ptr %lookup_elem77, i64 1 seq_cst, align 8
  br label %lookup_merge80

lookup_failure79:                                 ; preds = %event_loss_counter73
  br label %lookup_merge80

lookup_merge80:                                   ; preds = %lookup_failure79, %lookup_success78
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key76)
  br label %counter_merge74
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

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #3

attributes #0 = { nounwind }
attributes #1 = { alwaysinline }
attributes #2 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #3 = { nocallback nofree nounwind willreturn memory(argmem: write) }

!llvm.dbg.cu = !{!90}
!llvm.module.flags = !{!92}

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
!17 = !DICompositeType(tag: DW_TAG_array_type, baseType: !18, size: 192, elements: !19)
!18 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!19 = !{!20}
!20 = !DISubrange(count: 24, lowerBound: 0)
!21 = !DIGlobalVariableExpression(var: !22, expr: !DIExpression())
!22 = distinct !DIGlobalVariable(name: "AT_y", linkageName: "global", scope: !2, file: !2, type: !23, isLocal: false, isDefinition: true)
!23 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !24)
!24 = !{!5, !11, !12, !25}
!25 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !26, size: 64, offset: 192)
!26 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !27, size: 64)
!27 = !DICompositeType(tag: DW_TAG_array_type, baseType: !18, size: 128, elements: !28)
!28 = !{!29}
!29 = !DISubrange(count: 16, lowerBound: 0)
!30 = !DIGlobalVariableExpression(var: !31, expr: !DIExpression())
!31 = distinct !DIGlobalVariable(name: "stack_bpftrace_127", linkageName: "global", scope: !2, file: !2, type: !32, isLocal: false, isDefinition: true)
!32 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !33)
!33 = !{!34, !39, !44, !49}
!34 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !35, size: 64)
!35 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !36, size: 64)
!36 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 288, elements: !37)
!37 = !{!38}
!38 = !DISubrange(count: 9, lowerBound: 0)
!39 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !40, size: 64, offset: 64)
!40 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !41, size: 64)
!41 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 4194304, elements: !42)
!42 = !{!43}
!43 = !DISubrange(count: 131072, lowerBound: 0)
!44 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !45, size: 64, offset: 128)
!45 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !46, size: 64)
!46 = !DICompositeType(tag: DW_TAG_array_type, baseType: !18, size: 96, elements: !47)
!47 = !{!48}
!48 = !DISubrange(count: 12, lowerBound: 0)
!49 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !50, size: 64, offset: 192)
!50 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !51, size: 64)
!51 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 8128, elements: !52)
!52 = !{!53}
!53 = !DISubrange(count: 127, lowerBound: 0)
!54 = !DIGlobalVariableExpression(var: !55, expr: !DIExpression())
!55 = distinct !DIGlobalVariable(name: "stack_scratch", linkageName: "global", scope: !2, file: !2, type: !56, isLocal: false, isDefinition: true)
!56 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !57)
!57 = !{!58, !11, !63, !49}
!58 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !59, size: 64)
!59 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !60, size: 64)
!60 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 192, elements: !61)
!61 = !{!62}
!62 = !DISubrange(count: 6, lowerBound: 0)
!63 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !64, size: 64, offset: 128)
!64 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !65, size: 64)
!65 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!66 = !DIGlobalVariableExpression(var: !67, expr: !DIExpression())
!67 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !68, isLocal: false, isDefinition: true)
!68 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !69)
!69 = !{!70, !75}
!70 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !71, size: 64)
!71 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !72, size: 64)
!72 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !73)
!73 = !{!74}
!74 = !DISubrange(count: 27, lowerBound: 0)
!75 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !76, size: 64, offset: 64)
!76 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !77, size: 64)
!77 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !78)
!78 = !{!79}
!79 = !DISubrange(count: 262144, lowerBound: 0)
!80 = !DIGlobalVariableExpression(var: !81, expr: !DIExpression())
!81 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !82, isLocal: false, isDefinition: true)
!82 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !83)
!83 = !{!84, !11, !63, !89}
!84 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !85, size: 64)
!85 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !86, size: 64)
!86 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !87)
!87 = !{!88}
!88 = !DISubrange(count: 2, lowerBound: 0)
!89 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !13, size: 64, offset: 192)
!90 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !91)
!91 = !{!0, !21, !30, !54, !66, !80}
!92 = !{i32 2, !"Debug Info Version", i32 3}
!93 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !94, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !90, retainedNodes: !97)
!94 = !DISubroutineType(types: !95)
!95 = !{!14, !96}
!96 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !18, size: 64)
!97 = !{!98}
!98 = !DILocalVariable(name: "ctx", arg: 1, scope: !93, file: !2, type: !96)
