; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%"struct map_internal_repr_t" = type { ptr, ptr, ptr, ptr }
%"struct map_internal_repr_t.140" = type { ptr, ptr, ptr, ptr }
%"struct map_internal_repr_t.141" = type { ptr, ptr, ptr, ptr }
%"struct map_internal_repr_t.142" = type { ptr, ptr, ptr, ptr }
%"struct map_internal_repr_t.143" = type { ptr, ptr }
%runtime_error_t = type <{ i64, i64, i32 }>
%kstack_key = type { i64, i64 }
%ustack_key = type { i64, i64, i32, i32 }

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@AT_x = dso_local global %"struct map_internal_repr_t" zeroinitializer, section ".maps", !dbg !7
@AT_y = dso_local global %"struct map_internal_repr_t.140" zeroinitializer, section ".maps", !dbg !26
@stack_bpftrace_127 = dso_local global %"struct map_internal_repr_t.141" zeroinitializer, section ".maps", !dbg !35
@stack_scratch = dso_local global %"struct map_internal_repr_t.142" zeroinitializer, section ".maps", !dbg !55
@ringbuf = dso_local global %"struct map_internal_repr_t.143" zeroinitializer, section ".maps", !dbg !67
@__bt__event_loss_counter = dso_local externally_initialized global [1 x [1 x i64]] zeroinitializer, section ".data.event_loss_counter", !dbg !81
@__bt__max_cpu_id = dso_local externally_initialized constant i64 0, section ".rodata", !dbg !85

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

; Function Attrs: nounwind
define i64 @kprobe_f_1(ptr %0) #0 section "s_kprobe_f_1" !dbg !91 {
entry:
  %runtime_error_t55 = alloca %runtime_error_t, align 8
  %"@y_key" = alloca i64, align 8
  %runtime_error_t45 = alloca %runtime_error_t, align 8
  %runtime_error_t34 = alloca %runtime_error_t, align 8
  %lookup_stack_scratch_key23 = alloca i32, align 4
  %stack_key20 = alloca %kstack_key, align 8
  %runtime_error_t13 = alloca %runtime_error_t, align 8
  %"@x_key" = alloca i64, align 8
  %runtime_error_t3 = alloca %runtime_error_t, align 8
  %runtime_error_t = alloca %runtime_error_t, align 8
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
  %get_pid_tgid = call i64 inttoptr (i64 14 to ptr)() #4
  %2 = lshr i64 %get_pid_tgid, 32
  %pid = trunc i64 %2 to i32
  store i32 %pid, ptr %1, align 4
  %3 = getelementptr %ustack_key, ptr %stack_key, i64 0, i32 3
  store i32 0, ptr %3, align 4
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key")
  store i64 0, ptr %"@x_key", align 8
  %update_elem10 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %"@x_key", ptr %stack_key, i64 0)
  %4 = trunc i64 %update_elem10 to i32
  %5 = icmp sge i32 %4, 0
  br i1 %5, label %helper_merge12, label %helper_failure11

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
  call void @llvm.lifetime.start.p0(i64 -1, ptr %runtime_error_t)
  %14 = getelementptr %runtime_error_t, ptr %runtime_error_t, i64 0, i32 0
  store i64 30006, ptr %14, align 8
  %15 = getelementptr %runtime_error_t, ptr %runtime_error_t, i64 0, i32 1
  store i64 0, ptr %15, align 8
  %16 = getelementptr %runtime_error_t, ptr %runtime_error_t, i64 0, i32 2
  store i32 %6, ptr %16, align 4
  %ringbuf_output = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %runtime_error_t, i64 20, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

helper_merge:                                     ; preds = %counter_merge, %lookup_stack_scratch_merge
  %17 = icmp sge i64 %get_stack, 0
  br i1 %17, label %get_stack_success, label %get_stack_fail

event_loss_counter:                               ; preds = %helper_failure
  %get_cpu_id = call i64 inttoptr (i64 8 to ptr)() #4
  %18 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded = and i64 %get_cpu_id, %18
  %19 = getelementptr [1 x [1 x i64]], ptr @__bt__event_loss_counter, i64 0, i64 %cpu.id.bounded, i64 0
  %20 = load i64, ptr %19, align 8
  %21 = add i64 %20, 1
  store i64 %21, ptr %19, align 8
  br label %counter_merge

counter_merge:                                    ; preds = %event_loss_counter, %helper_failure
  call void @llvm.lifetime.end.p0(i64 -1, ptr %runtime_error_t)
  br label %helper_merge

helper_failure1:                                  ; preds = %get_stack_success
  call void @llvm.lifetime.start.p0(i64 -1, ptr %runtime_error_t3)
  %22 = getelementptr %runtime_error_t, ptr %runtime_error_t3, i64 0, i32 0
  store i64 30006, ptr %22, align 8
  %23 = getelementptr %runtime_error_t, ptr %runtime_error_t3, i64 0, i32 1
  store i64 1, ptr %23, align 8
  %24 = getelementptr %runtime_error_t, ptr %runtime_error_t3, i64 0, i32 2
  store i32 %12, ptr %24, align 4
  %ringbuf_output4 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %runtime_error_t3, i64 20, i64 0)
  %ringbuf_loss7 = icmp slt i64 %ringbuf_output4, 0
  br i1 %ringbuf_loss7, label %event_loss_counter5, label %counter_merge6

helper_merge2:                                    ; preds = %counter_merge6, %get_stack_success
  br label %merge_block

event_loss_counter5:                              ; preds = %helper_failure1
  %get_cpu_id8 = call i64 inttoptr (i64 8 to ptr)() #4
  %25 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded9 = and i64 %get_cpu_id8, %25
  %26 = getelementptr [1 x [1 x i64]], ptr @__bt__event_loss_counter, i64 0, i64 %cpu.id.bounded9, i64 0
  %27 = load i64, ptr %26, align 8
  %28 = add i64 %27, 1
  store i64 %28, ptr %26, align 8
  br label %counter_merge6

counter_merge6:                                   ; preds = %event_loss_counter5, %helper_failure1
  call void @llvm.lifetime.end.p0(i64 -1, ptr %runtime_error_t3)
  br label %helper_merge2

helper_failure11:                                 ; preds = %merge_block
  call void @llvm.lifetime.start.p0(i64 -1, ptr %runtime_error_t13)
  %29 = getelementptr %runtime_error_t, ptr %runtime_error_t13, i64 0, i32 0
  store i64 30006, ptr %29, align 8
  %30 = getelementptr %runtime_error_t, ptr %runtime_error_t13, i64 0, i32 1
  store i64 2, ptr %30, align 8
  %31 = getelementptr %runtime_error_t, ptr %runtime_error_t13, i64 0, i32 2
  store i32 %4, ptr %31, align 4
  %ringbuf_output14 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %runtime_error_t13, i64 20, i64 0)
  %ringbuf_loss17 = icmp slt i64 %ringbuf_output14, 0
  br i1 %ringbuf_loss17, label %event_loss_counter15, label %counter_merge16

helper_merge12:                                   ; preds = %counter_merge16, %merge_block
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %stack_key20)
  call void @llvm.memset.p0.i64(ptr align 1 %stack_key20, i8 0, i64 16, i1 false)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_stack_scratch_key23)
  store i32 0, ptr %lookup_stack_scratch_key23, align 4
  %lookup_stack_scratch_map24 = call ptr inttoptr (i64 1 to ptr)(ptr @stack_scratch, ptr %lookup_stack_scratch_key23)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_stack_scratch_key23)
  %lookup_stack_scratch_cond27 = icmp ne ptr %lookup_stack_scratch_map24, null
  br i1 %lookup_stack_scratch_cond27, label %lookup_stack_scratch_merge26, label %lookup_stack_scratch_failure25

event_loss_counter15:                             ; preds = %helper_failure11
  %get_cpu_id18 = call i64 inttoptr (i64 8 to ptr)() #4
  %32 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded19 = and i64 %get_cpu_id18, %32
  %33 = getelementptr [1 x [1 x i64]], ptr @__bt__event_loss_counter, i64 0, i64 %cpu.id.bounded19, i64 0
  %34 = load i64, ptr %33, align 8
  %35 = add i64 %34, 1
  store i64 %35, ptr %33, align 8
  br label %counter_merge16

counter_merge16:                                  ; preds = %event_loss_counter15, %helper_failure11
  call void @llvm.lifetime.end.p0(i64 -1, ptr %runtime_error_t13)
  br label %helper_merge12

stack_scratch_failure21:                          ; preds = %lookup_stack_scratch_failure25
  br label %merge_block22

merge_block22:                                    ; preds = %stack_scratch_failure21, %helper_merge44, %get_stack_fail30
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@y_key")
  store i64 0, ptr %"@y_key", align 8
  %update_elem52 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_y, ptr %"@y_key", ptr %stack_key20, i64 0)
  %36 = trunc i64 %update_elem52 to i32
  %37 = icmp sge i32 %36, 0
  br i1 %37, label %helper_merge54, label %helper_failure53

lookup_stack_scratch_failure25:                   ; preds = %helper_merge12
  br label %stack_scratch_failure21

lookup_stack_scratch_merge26:                     ; preds = %helper_merge12
  %probe_read_kernel28 = call i64 inttoptr (i64 113 to ptr)(ptr %lookup_stack_scratch_map24, i32 1016, ptr null)
  %get_stack31 = call i64 inttoptr (i64 67 to ptr)(ptr %0, ptr %lookup_stack_scratch_map24, i32 1016, i64 0)
  %38 = trunc i64 %get_stack31 to i32
  %39 = icmp sge i32 %38, 0
  br i1 %39, label %helper_merge33, label %helper_failure32

get_stack_success29:                              ; preds = %helper_merge33
  %40 = udiv i64 %get_stack31, 8
  %41 = getelementptr %kstack_key, ptr %stack_key20, i64 0, i32 1
  store i64 %40, ptr %41, align 8
  %42 = trunc i64 %40 to i8
  %murmur_hash_241 = call i64 @murmur_hash_2(ptr %lookup_stack_scratch_map24, i8 %42, i64 1)
  %43 = getelementptr %kstack_key, ptr %stack_key20, i64 0, i32 0
  store i64 %murmur_hash_241, ptr %43, align 8
  %update_elem42 = call i64 inttoptr (i64 2 to ptr)(ptr @stack_bpftrace_127, ptr %stack_key20, ptr %lookup_stack_scratch_map24, i64 0)
  %44 = trunc i64 %update_elem42 to i32
  %45 = icmp sge i32 %44, 0
  br i1 %45, label %helper_merge44, label %helper_failure43

get_stack_fail30:                                 ; preds = %helper_merge33
  br label %merge_block22

helper_failure32:                                 ; preds = %lookup_stack_scratch_merge26
  call void @llvm.lifetime.start.p0(i64 -1, ptr %runtime_error_t34)
  %46 = getelementptr %runtime_error_t, ptr %runtime_error_t34, i64 0, i32 0
  store i64 30006, ptr %46, align 8
  %47 = getelementptr %runtime_error_t, ptr %runtime_error_t34, i64 0, i32 1
  store i64 3, ptr %47, align 8
  %48 = getelementptr %runtime_error_t, ptr %runtime_error_t34, i64 0, i32 2
  store i32 %38, ptr %48, align 4
  %ringbuf_output35 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %runtime_error_t34, i64 20, i64 0)
  %ringbuf_loss38 = icmp slt i64 %ringbuf_output35, 0
  br i1 %ringbuf_loss38, label %event_loss_counter36, label %counter_merge37

helper_merge33:                                   ; preds = %counter_merge37, %lookup_stack_scratch_merge26
  %49 = icmp sge i64 %get_stack31, 0
  br i1 %49, label %get_stack_success29, label %get_stack_fail30

event_loss_counter36:                             ; preds = %helper_failure32
  %get_cpu_id39 = call i64 inttoptr (i64 8 to ptr)() #4
  %50 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded40 = and i64 %get_cpu_id39, %50
  %51 = getelementptr [1 x [1 x i64]], ptr @__bt__event_loss_counter, i64 0, i64 %cpu.id.bounded40, i64 0
  %52 = load i64, ptr %51, align 8
  %53 = add i64 %52, 1
  store i64 %53, ptr %51, align 8
  br label %counter_merge37

counter_merge37:                                  ; preds = %event_loss_counter36, %helper_failure32
  call void @llvm.lifetime.end.p0(i64 -1, ptr %runtime_error_t34)
  br label %helper_merge33

helper_failure43:                                 ; preds = %get_stack_success29
  call void @llvm.lifetime.start.p0(i64 -1, ptr %runtime_error_t45)
  %54 = getelementptr %runtime_error_t, ptr %runtime_error_t45, i64 0, i32 0
  store i64 30006, ptr %54, align 8
  %55 = getelementptr %runtime_error_t, ptr %runtime_error_t45, i64 0, i32 1
  store i64 4, ptr %55, align 8
  %56 = getelementptr %runtime_error_t, ptr %runtime_error_t45, i64 0, i32 2
  store i32 %44, ptr %56, align 4
  %ringbuf_output46 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %runtime_error_t45, i64 20, i64 0)
  %ringbuf_loss49 = icmp slt i64 %ringbuf_output46, 0
  br i1 %ringbuf_loss49, label %event_loss_counter47, label %counter_merge48

helper_merge44:                                   ; preds = %counter_merge48, %get_stack_success29
  br label %merge_block22

event_loss_counter47:                             ; preds = %helper_failure43
  %get_cpu_id50 = call i64 inttoptr (i64 8 to ptr)() #4
  %57 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded51 = and i64 %get_cpu_id50, %57
  %58 = getelementptr [1 x [1 x i64]], ptr @__bt__event_loss_counter, i64 0, i64 %cpu.id.bounded51, i64 0
  %59 = load i64, ptr %58, align 8
  %60 = add i64 %59, 1
  store i64 %60, ptr %58, align 8
  br label %counter_merge48

counter_merge48:                                  ; preds = %event_loss_counter47, %helper_failure43
  call void @llvm.lifetime.end.p0(i64 -1, ptr %runtime_error_t45)
  br label %helper_merge44

helper_failure53:                                 ; preds = %merge_block22
  call void @llvm.lifetime.start.p0(i64 -1, ptr %runtime_error_t55)
  %61 = getelementptr %runtime_error_t, ptr %runtime_error_t55, i64 0, i32 0
  store i64 30006, ptr %61, align 8
  %62 = getelementptr %runtime_error_t, ptr %runtime_error_t55, i64 0, i32 1
  store i64 5, ptr %62, align 8
  %63 = getelementptr %runtime_error_t, ptr %runtime_error_t55, i64 0, i32 2
  store i32 %36, ptr %63, align 4
  %ringbuf_output56 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %runtime_error_t55, i64 20, i64 0)
  %ringbuf_loss59 = icmp slt i64 %ringbuf_output56, 0
  br i1 %ringbuf_loss59, label %event_loss_counter57, label %counter_merge58

helper_merge54:                                   ; preds = %counter_merge58, %merge_block22
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@y_key")
  ret i64 0

event_loss_counter57:                             ; preds = %helper_failure53
  %get_cpu_id60 = call i64 inttoptr (i64 8 to ptr)() #4
  %64 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded61 = and i64 %get_cpu_id60, %64
  %65 = getelementptr [1 x [1 x i64]], ptr @__bt__event_loss_counter, i64 0, i64 %cpu.id.bounded61, i64 0
  %66 = load i64, ptr %65, align 8
  %67 = add i64 %66, 1
  store i64 %67, ptr %65, align 8
  br label %counter_merge58

counter_merge58:                                  ; preds = %event_loss_counter57, %helper_failure53
  call void @llvm.lifetime.end.p0(i64 -1, ptr %runtime_error_t55)
  br label %helper_merge54
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
attributes #4 = { memory(none) }

!llvm.dbg.cu = !{!87}
!llvm.module.flags = !{!89, !90}

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
!82 = distinct !DIGlobalVariable(name: "__bt__event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !83, isLocal: false, isDefinition: true)
!83 = !DICompositeType(tag: DW_TAG_array_type, baseType: !84, size: 64, elements: !15)
!84 = !DICompositeType(tag: DW_TAG_array_type, baseType: !20, size: 64, elements: !15)
!85 = !DIGlobalVariableExpression(var: !86, expr: !DIExpression())
!86 = distinct !DIGlobalVariable(name: "__bt__max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !20, isLocal: false, isDefinition: true)
!87 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !88)
!88 = !{!0, !7, !26, !35, !55, !67, !81, !85}
!89 = !{i32 2, !"Debug Info Version", i32 3}
!90 = !{i32 7, !"uwtable", i32 0}
!91 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !92, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !87, retainedNodes: !95)
!92 = !DISubroutineType(types: !93)
!93 = !{!20, !94}
!94 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!95 = !{!96}
!96 = !DILocalVariable(name: "ctx", arg: 1, scope: !91, file: !2, type: !94)
