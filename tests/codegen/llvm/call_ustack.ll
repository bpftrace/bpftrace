; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr, ptr, ptr }
%"struct map_t.1" = type { ptr, ptr, ptr, ptr }
%"struct map_t.2" = type { ptr, ptr, ptr, ptr }
%"struct map_t.3" = type { ptr, ptr, ptr, ptr }
%"struct map_t.4" = type { ptr, ptr, ptr, ptr }
%"struct map_t.5" = type { ptr, ptr, ptr, ptr }
%"struct map_t.6" = type { ptr, ptr }
%"struct map_t.7" = type { ptr, ptr, ptr, ptr }
%helper_error_t = type <{ i64, i64, i32 }>
%ustack_key = type { i64, i32, i32, i32 }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_x = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@AT_y = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !21
@AT_z = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !23
@stack_perf_127 = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !25
@stack_bpftrace_6 = dso_local global %"struct map_t.3" zeroinitializer, section ".maps", !dbg !49
@stack_bpftrace_127 = dso_local global %"struct map_t.4" zeroinitializer, section ".maps", !dbg !58
@stack_scratch = dso_local global %"struct map_t.5" zeroinitializer, section ".maps", !dbg !60
@ringbuf = dso_local global %"struct map_t.6" zeroinitializer, section ".maps", !dbg !70
@event_loss_counter = dso_local global %"struct map_t.7" zeroinitializer, section ".maps", !dbg !84

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(ptr %0) section "s_kprobe_f_1" !dbg !97 {
entry:
  %key133 = alloca i32, align 4
  %helper_error_t128 = alloca %helper_error_t, align 8
  %"@z_key" = alloca i64, align 8
  %key117 = alloca i32, align 4
  %helper_error_t112 = alloca %helper_error_t, align 8
  %key102 = alloca i32, align 4
  %helper_error_t97 = alloca %helper_error_t, align 8
  %lookup_stack_scratch_key86 = alloca i32, align 4
  %stack_key83 = alloca %ustack_key, align 8
  %key77 = alloca i32, align 4
  %helper_error_t72 = alloca %helper_error_t, align 8
  %"@y_key" = alloca i64, align 8
  %key61 = alloca i32, align 4
  %helper_error_t56 = alloca %helper_error_t, align 8
  %key46 = alloca i32, align 4
  %helper_error_t41 = alloca %helper_error_t, align 8
  %lookup_stack_scratch_key31 = alloca i32, align 4
  %stack_key28 = alloca %ustack_key, align 8
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
  %1 = getelementptr %ustack_key, ptr %stack_key, i64 0, i32 0
  store i64 0, ptr %1, align 8
  %2 = getelementptr %ustack_key, ptr %stack_key, i64 0, i32 1
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
  %3 = getelementptr %ustack_key, ptr %stack_key, i64 0, i32 2
  %get_pid_tgid = call i64 inttoptr (i64 14 to ptr)()
  %4 = lshr i64 %get_pid_tgid, 32
  %pid = trunc i64 %4 to i32
  store i32 %pid, ptr %3, align 4
  %5 = getelementptr %ustack_key, ptr %stack_key, i64 0, i32 3
  store i32 0, ptr %5, align 4
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key")
  store i64 0, ptr %"@x_key", align 8
  %update_elem14 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %"@x_key", ptr %stack_key, i64 0)
  %6 = trunc i64 %update_elem14 to i32
  %7 = icmp sge i32 %6, 0
  br i1 %7, label %helper_merge16, label %helper_failure15

lookup_stack_scratch_failure:                     ; preds = %entry
  br label %stack_scratch_failure

lookup_stack_scratch_merge:                       ; preds = %entry
  %probe_read_kernel = call i64 inttoptr (i64 113 to ptr)(ptr %lookup_stack_scratch_map, i32 1016, ptr null)
  %get_stack = call i32 inttoptr (i64 67 to ptr)(ptr %0, ptr %lookup_stack_scratch_map, i32 1016, i64 256)
  %8 = icmp sge i32 %get_stack, 0
  br i1 %8, label %helper_merge, label %helper_failure

get_stack_success:                                ; preds = %helper_merge
  %9 = udiv i32 %get_stack, 8
  %10 = getelementptr %ustack_key, ptr %stack_key, i64 0, i32 1
  store i32 %9, ptr %10, align 4
  %11 = trunc i32 %9 to i8
  %murmur_hash_2 = call i64 @murmur_hash_2(ptr %lookup_stack_scratch_map, i8 %11, i64 1)
  %12 = getelementptr %ustack_key, ptr %stack_key, i64 0, i32 0
  store i64 %murmur_hash_2, ptr %12, align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @stack_bpftrace_127, ptr %stack_key, ptr %lookup_stack_scratch_map, i64 0)
  %13 = trunc i64 %update_elem to i32
  %14 = icmp sge i32 %13, 0
  br i1 %14, label %helper_merge2, label %helper_failure1

get_stack_fail:                                   ; preds = %helper_merge
  br label %merge_block

helper_failure:                                   ; preds = %lookup_stack_scratch_merge
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t)
  %15 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 0
  store i64 30006, ptr %15, align 8
  %16 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 1
  store i64 0, ptr %16, align 8
  %17 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 2
  store i32 %get_stack, ptr %17, align 4
  %ringbuf_output = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t, i64 20, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

helper_merge:                                     ; preds = %counter_merge, %lookup_stack_scratch_merge
  %18 = icmp sge i32 %get_stack, 0
  br i1 %18, label %get_stack_success, label %get_stack_fail

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
  %19 = atomicrmw add ptr %lookup_elem, i64 1 seq_cst, align 8
  br label %lookup_merge

lookup_failure:                                   ; preds = %event_loss_counter
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key)
  br label %counter_merge

helper_failure1:                                  ; preds = %get_stack_success
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t3)
  %20 = getelementptr %helper_error_t, ptr %helper_error_t3, i64 0, i32 0
  store i64 30006, ptr %20, align 8
  %21 = getelementptr %helper_error_t, ptr %helper_error_t3, i64 0, i32 1
  store i64 1, ptr %21, align 8
  %22 = getelementptr %helper_error_t, ptr %helper_error_t3, i64 0, i32 2
  store i32 %13, ptr %22, align 4
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
  %23 = atomicrmw add ptr %lookup_elem9, i64 1 seq_cst, align 8
  br label %lookup_merge12

lookup_failure11:                                 ; preds = %event_loss_counter5
  br label %lookup_merge12

lookup_merge12:                                   ; preds = %lookup_failure11, %lookup_success10
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key8)
  br label %counter_merge6

helper_failure15:                                 ; preds = %merge_block
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t17)
  %24 = getelementptr %helper_error_t, ptr %helper_error_t17, i64 0, i32 0
  store i64 30006, ptr %24, align 8
  %25 = getelementptr %helper_error_t, ptr %helper_error_t17, i64 0, i32 1
  store i64 2, ptr %25, align 8
  %26 = getelementptr %helper_error_t, ptr %helper_error_t17, i64 0, i32 2
  store i32 %6, ptr %26, align 4
  %ringbuf_output18 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t17, i64 20, i64 0)
  %ringbuf_loss21 = icmp slt i64 %ringbuf_output18, 0
  br i1 %ringbuf_loss21, label %event_loss_counter19, label %counter_merge20

helper_merge16:                                   ; preds = %counter_merge20, %merge_block
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %stack_key28)
  %27 = getelementptr %ustack_key, ptr %stack_key28, i64 0, i32 0
  store i64 0, ptr %27, align 8
  %28 = getelementptr %ustack_key, ptr %stack_key28, i64 0, i32 1
  store i32 0, ptr %28, align 4
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
  %29 = atomicrmw add ptr %lookup_elem23, i64 1 seq_cst, align 8
  br label %lookup_merge26

lookup_failure25:                                 ; preds = %event_loss_counter19
  br label %lookup_merge26

lookup_merge26:                                   ; preds = %lookup_failure25, %lookup_success24
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key22)
  br label %counter_merge20

stack_scratch_failure29:                          ; preds = %lookup_stack_scratch_failure33
  br label %merge_block30

merge_block30:                                    ; preds = %stack_scratch_failure29, %helper_merge55, %get_stack_fail37
  %30 = getelementptr %ustack_key, ptr %stack_key28, i64 0, i32 2
  %get_pid_tgid67 = call i64 inttoptr (i64 14 to ptr)()
  %31 = lshr i64 %get_pid_tgid67, 32
  %pid68 = trunc i64 %31 to i32
  store i32 %pid68, ptr %30, align 4
  %32 = getelementptr %ustack_key, ptr %stack_key28, i64 0, i32 3
  store i32 0, ptr %32, align 4
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@y_key")
  store i64 0, ptr %"@y_key", align 8
  %update_elem69 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_y, ptr %"@y_key", ptr %stack_key28, i64 0)
  %33 = trunc i64 %update_elem69 to i32
  %34 = icmp sge i32 %33, 0
  br i1 %34, label %helper_merge71, label %helper_failure70

lookup_stack_scratch_failure33:                   ; preds = %helper_merge16
  br label %stack_scratch_failure29

lookup_stack_scratch_merge34:                     ; preds = %helper_merge16
  call void @llvm.memset.p0.i64(ptr align 1 %lookup_stack_scratch_map32, i8 0, i64 48, i1 false)
  %get_stack38 = call i32 inttoptr (i64 67 to ptr)(ptr %0, ptr %lookup_stack_scratch_map32, i32 48, i64 256)
  %35 = icmp sge i32 %get_stack38, 0
  br i1 %35, label %helper_merge40, label %helper_failure39

get_stack_success36:                              ; preds = %helper_merge40
  %36 = udiv i32 %get_stack38, 8
  %37 = getelementptr %ustack_key, ptr %stack_key28, i64 0, i32 1
  store i32 %36, ptr %37, align 4
  %38 = trunc i32 %36 to i8
  %murmur_hash_252 = call i64 @murmur_hash_2(ptr %lookup_stack_scratch_map32, i8 %38, i64 1)
  %39 = getelementptr %ustack_key, ptr %stack_key28, i64 0, i32 0
  store i64 %murmur_hash_252, ptr %39, align 8
  %update_elem53 = call i64 inttoptr (i64 2 to ptr)(ptr @stack_bpftrace_6, ptr %stack_key28, ptr %lookup_stack_scratch_map32, i64 0)
  %40 = trunc i64 %update_elem53 to i32
  %41 = icmp sge i32 %40, 0
  br i1 %41, label %helper_merge55, label %helper_failure54

get_stack_fail37:                                 ; preds = %helper_merge40
  br label %merge_block30

helper_failure39:                                 ; preds = %lookup_stack_scratch_merge34
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t41)
  %42 = getelementptr %helper_error_t, ptr %helper_error_t41, i64 0, i32 0
  store i64 30006, ptr %42, align 8
  %43 = getelementptr %helper_error_t, ptr %helper_error_t41, i64 0, i32 1
  store i64 3, ptr %43, align 8
  %44 = getelementptr %helper_error_t, ptr %helper_error_t41, i64 0, i32 2
  store i32 %get_stack38, ptr %44, align 4
  %ringbuf_output42 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t41, i64 20, i64 0)
  %ringbuf_loss45 = icmp slt i64 %ringbuf_output42, 0
  br i1 %ringbuf_loss45, label %event_loss_counter43, label %counter_merge44

helper_merge40:                                   ; preds = %counter_merge44, %lookup_stack_scratch_merge34
  %45 = icmp sge i32 %get_stack38, 0
  br i1 %45, label %get_stack_success36, label %get_stack_fail37

event_loss_counter43:                             ; preds = %helper_failure39
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key46)
  store i32 0, ptr %key46, align 4
  %lookup_elem47 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key46)
  %map_lookup_cond51 = icmp ne ptr %lookup_elem47, null
  br i1 %map_lookup_cond51, label %lookup_success48, label %lookup_failure49

counter_merge44:                                  ; preds = %lookup_merge50, %helper_failure39
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t41)
  br label %helper_merge40

lookup_success48:                                 ; preds = %event_loss_counter43
  %46 = atomicrmw add ptr %lookup_elem47, i64 1 seq_cst, align 8
  br label %lookup_merge50

lookup_failure49:                                 ; preds = %event_loss_counter43
  br label %lookup_merge50

lookup_merge50:                                   ; preds = %lookup_failure49, %lookup_success48
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key46)
  br label %counter_merge44

helper_failure54:                                 ; preds = %get_stack_success36
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t56)
  %47 = getelementptr %helper_error_t, ptr %helper_error_t56, i64 0, i32 0
  store i64 30006, ptr %47, align 8
  %48 = getelementptr %helper_error_t, ptr %helper_error_t56, i64 0, i32 1
  store i64 4, ptr %48, align 8
  %49 = getelementptr %helper_error_t, ptr %helper_error_t56, i64 0, i32 2
  store i32 %40, ptr %49, align 4
  %ringbuf_output57 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t56, i64 20, i64 0)
  %ringbuf_loss60 = icmp slt i64 %ringbuf_output57, 0
  br i1 %ringbuf_loss60, label %event_loss_counter58, label %counter_merge59

helper_merge55:                                   ; preds = %counter_merge59, %get_stack_success36
  br label %merge_block30

event_loss_counter58:                             ; preds = %helper_failure54
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key61)
  store i32 0, ptr %key61, align 4
  %lookup_elem62 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key61)
  %map_lookup_cond66 = icmp ne ptr %lookup_elem62, null
  br i1 %map_lookup_cond66, label %lookup_success63, label %lookup_failure64

counter_merge59:                                  ; preds = %lookup_merge65, %helper_failure54
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t56)
  br label %helper_merge55

lookup_success63:                                 ; preds = %event_loss_counter58
  %50 = atomicrmw add ptr %lookup_elem62, i64 1 seq_cst, align 8
  br label %lookup_merge65

lookup_failure64:                                 ; preds = %event_loss_counter58
  br label %lookup_merge65

lookup_merge65:                                   ; preds = %lookup_failure64, %lookup_success63
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key61)
  br label %counter_merge59

helper_failure70:                                 ; preds = %merge_block30
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t72)
  %51 = getelementptr %helper_error_t, ptr %helper_error_t72, i64 0, i32 0
  store i64 30006, ptr %51, align 8
  %52 = getelementptr %helper_error_t, ptr %helper_error_t72, i64 0, i32 1
  store i64 5, ptr %52, align 8
  %53 = getelementptr %helper_error_t, ptr %helper_error_t72, i64 0, i32 2
  store i32 %33, ptr %53, align 4
  %ringbuf_output73 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t72, i64 20, i64 0)
  %ringbuf_loss76 = icmp slt i64 %ringbuf_output73, 0
  br i1 %ringbuf_loss76, label %event_loss_counter74, label %counter_merge75

helper_merge71:                                   ; preds = %counter_merge75, %merge_block30
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@y_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %stack_key83)
  %54 = getelementptr %ustack_key, ptr %stack_key83, i64 0, i32 0
  store i64 0, ptr %54, align 8
  %55 = getelementptr %ustack_key, ptr %stack_key83, i64 0, i32 1
  store i32 0, ptr %55, align 4
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_stack_scratch_key86)
  store i32 0, ptr %lookup_stack_scratch_key86, align 4
  %lookup_stack_scratch_map87 = call ptr inttoptr (i64 1 to ptr)(ptr @stack_scratch, ptr %lookup_stack_scratch_key86)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_stack_scratch_key86)
  %lookup_stack_scratch_cond90 = icmp ne ptr %lookup_stack_scratch_map87, null
  br i1 %lookup_stack_scratch_cond90, label %lookup_stack_scratch_merge89, label %lookup_stack_scratch_failure88

event_loss_counter74:                             ; preds = %helper_failure70
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key77)
  store i32 0, ptr %key77, align 4
  %lookup_elem78 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key77)
  %map_lookup_cond82 = icmp ne ptr %lookup_elem78, null
  br i1 %map_lookup_cond82, label %lookup_success79, label %lookup_failure80

counter_merge75:                                  ; preds = %lookup_merge81, %helper_failure70
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t72)
  br label %helper_merge71

lookup_success79:                                 ; preds = %event_loss_counter74
  %56 = atomicrmw add ptr %lookup_elem78, i64 1 seq_cst, align 8
  br label %lookup_merge81

lookup_failure80:                                 ; preds = %event_loss_counter74
  br label %lookup_merge81

lookup_merge81:                                   ; preds = %lookup_failure80, %lookup_success79
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key77)
  br label %counter_merge75

stack_scratch_failure84:                          ; preds = %lookup_stack_scratch_failure88
  br label %merge_block85

merge_block85:                                    ; preds = %stack_scratch_failure84, %helper_merge111, %get_stack_fail93
  %57 = getelementptr %ustack_key, ptr %stack_key83, i64 0, i32 2
  %get_pid_tgid123 = call i64 inttoptr (i64 14 to ptr)()
  %58 = lshr i64 %get_pid_tgid123, 32
  %pid124 = trunc i64 %58 to i32
  store i32 %pid124, ptr %57, align 4
  %59 = getelementptr %ustack_key, ptr %stack_key83, i64 0, i32 3
  store i32 0, ptr %59, align 4
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@z_key")
  store i64 0, ptr %"@z_key", align 8
  %update_elem125 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_z, ptr %"@z_key", ptr %stack_key83, i64 0)
  %60 = trunc i64 %update_elem125 to i32
  %61 = icmp sge i32 %60, 0
  br i1 %61, label %helper_merge127, label %helper_failure126

lookup_stack_scratch_failure88:                   ; preds = %helper_merge71
  br label %stack_scratch_failure84

lookup_stack_scratch_merge89:                     ; preds = %helper_merge71
  %probe_read_kernel91 = call i64 inttoptr (i64 113 to ptr)(ptr %lookup_stack_scratch_map87, i32 1016, ptr null)
  %get_stack94 = call i32 inttoptr (i64 67 to ptr)(ptr %0, ptr %lookup_stack_scratch_map87, i32 1016, i64 256)
  %62 = icmp sge i32 %get_stack94, 0
  br i1 %62, label %helper_merge96, label %helper_failure95

get_stack_success92:                              ; preds = %helper_merge96
  %63 = udiv i32 %get_stack94, 8
  %64 = getelementptr %ustack_key, ptr %stack_key83, i64 0, i32 1
  store i32 %63, ptr %64, align 4
  %65 = trunc i32 %63 to i8
  %murmur_hash_2108 = call i64 @murmur_hash_2(ptr %lookup_stack_scratch_map87, i8 %65, i64 1)
  %66 = getelementptr %ustack_key, ptr %stack_key83, i64 0, i32 0
  store i64 %murmur_hash_2108, ptr %66, align 8
  %update_elem109 = call i64 inttoptr (i64 2 to ptr)(ptr @stack_perf_127, ptr %stack_key83, ptr %lookup_stack_scratch_map87, i64 0)
  %67 = trunc i64 %update_elem109 to i32
  %68 = icmp sge i32 %67, 0
  br i1 %68, label %helper_merge111, label %helper_failure110

get_stack_fail93:                                 ; preds = %helper_merge96
  br label %merge_block85

helper_failure95:                                 ; preds = %lookup_stack_scratch_merge89
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t97)
  %69 = getelementptr %helper_error_t, ptr %helper_error_t97, i64 0, i32 0
  store i64 30006, ptr %69, align 8
  %70 = getelementptr %helper_error_t, ptr %helper_error_t97, i64 0, i32 1
  store i64 6, ptr %70, align 8
  %71 = getelementptr %helper_error_t, ptr %helper_error_t97, i64 0, i32 2
  store i32 %get_stack94, ptr %71, align 4
  %ringbuf_output98 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t97, i64 20, i64 0)
  %ringbuf_loss101 = icmp slt i64 %ringbuf_output98, 0
  br i1 %ringbuf_loss101, label %event_loss_counter99, label %counter_merge100

helper_merge96:                                   ; preds = %counter_merge100, %lookup_stack_scratch_merge89
  %72 = icmp sge i32 %get_stack94, 0
  br i1 %72, label %get_stack_success92, label %get_stack_fail93

event_loss_counter99:                             ; preds = %helper_failure95
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key102)
  store i32 0, ptr %key102, align 4
  %lookup_elem103 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key102)
  %map_lookup_cond107 = icmp ne ptr %lookup_elem103, null
  br i1 %map_lookup_cond107, label %lookup_success104, label %lookup_failure105

counter_merge100:                                 ; preds = %lookup_merge106, %helper_failure95
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t97)
  br label %helper_merge96

lookup_success104:                                ; preds = %event_loss_counter99
  %73 = atomicrmw add ptr %lookup_elem103, i64 1 seq_cst, align 8
  br label %lookup_merge106

lookup_failure105:                                ; preds = %event_loss_counter99
  br label %lookup_merge106

lookup_merge106:                                  ; preds = %lookup_failure105, %lookup_success104
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key102)
  br label %counter_merge100

helper_failure110:                                ; preds = %get_stack_success92
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t112)
  %74 = getelementptr %helper_error_t, ptr %helper_error_t112, i64 0, i32 0
  store i64 30006, ptr %74, align 8
  %75 = getelementptr %helper_error_t, ptr %helper_error_t112, i64 0, i32 1
  store i64 7, ptr %75, align 8
  %76 = getelementptr %helper_error_t, ptr %helper_error_t112, i64 0, i32 2
  store i32 %67, ptr %76, align 4
  %ringbuf_output113 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t112, i64 20, i64 0)
  %ringbuf_loss116 = icmp slt i64 %ringbuf_output113, 0
  br i1 %ringbuf_loss116, label %event_loss_counter114, label %counter_merge115

helper_merge111:                                  ; preds = %counter_merge115, %get_stack_success92
  br label %merge_block85

event_loss_counter114:                            ; preds = %helper_failure110
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key117)
  store i32 0, ptr %key117, align 4
  %lookup_elem118 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key117)
  %map_lookup_cond122 = icmp ne ptr %lookup_elem118, null
  br i1 %map_lookup_cond122, label %lookup_success119, label %lookup_failure120

counter_merge115:                                 ; preds = %lookup_merge121, %helper_failure110
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t112)
  br label %helper_merge111

lookup_success119:                                ; preds = %event_loss_counter114
  %77 = atomicrmw add ptr %lookup_elem118, i64 1 seq_cst, align 8
  br label %lookup_merge121

lookup_failure120:                                ; preds = %event_loss_counter114
  br label %lookup_merge121

lookup_merge121:                                  ; preds = %lookup_failure120, %lookup_success119
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key117)
  br label %counter_merge115

helper_failure126:                                ; preds = %merge_block85
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t128)
  %78 = getelementptr %helper_error_t, ptr %helper_error_t128, i64 0, i32 0
  store i64 30006, ptr %78, align 8
  %79 = getelementptr %helper_error_t, ptr %helper_error_t128, i64 0, i32 1
  store i64 8, ptr %79, align 8
  %80 = getelementptr %helper_error_t, ptr %helper_error_t128, i64 0, i32 2
  store i32 %60, ptr %80, align 4
  %ringbuf_output129 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t128, i64 20, i64 0)
  %ringbuf_loss132 = icmp slt i64 %ringbuf_output129, 0
  br i1 %ringbuf_loss132, label %event_loss_counter130, label %counter_merge131

helper_merge127:                                  ; preds = %counter_merge131, %merge_block85
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@z_key")
  ret i64 0

event_loss_counter130:                            ; preds = %helper_failure126
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key133)
  store i32 0, ptr %key133, align 4
  %lookup_elem134 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key133)
  %map_lookup_cond138 = icmp ne ptr %lookup_elem134, null
  br i1 %map_lookup_cond138, label %lookup_success135, label %lookup_failure136

counter_merge131:                                 ; preds = %lookup_merge137, %helper_failure126
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t128)
  br label %helper_merge127

lookup_success135:                                ; preds = %event_loss_counter130
  %81 = atomicrmw add ptr %lookup_elem134, i64 1 seq_cst, align 8
  br label %lookup_merge137

lookup_failure136:                                ; preds = %event_loss_counter130
  br label %lookup_merge137

lookup_merge137:                                  ; preds = %lookup_failure136, %lookup_success135
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key133)
  br label %counter_merge131
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

!llvm.dbg.cu = !{!94}
!llvm.module.flags = !{!96}

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
!17 = !DICompositeType(tag: DW_TAG_array_type, baseType: !18, size: 160, elements: !19)
!18 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!19 = !{!20}
!20 = !DISubrange(count: 20, lowerBound: 0)
!21 = !DIGlobalVariableExpression(var: !22, expr: !DIExpression())
!22 = distinct !DIGlobalVariable(name: "AT_y", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!23 = !DIGlobalVariableExpression(var: !24, expr: !DIExpression())
!24 = distinct !DIGlobalVariable(name: "AT_z", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!25 = !DIGlobalVariableExpression(var: !26, expr: !DIExpression())
!26 = distinct !DIGlobalVariable(name: "stack_perf_127", linkageName: "global", scope: !2, file: !2, type: !27, isLocal: false, isDefinition: true)
!27 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !28)
!28 = !{!29, !34, !39, !44}
!29 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !30, size: 64)
!30 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !31, size: 64)
!31 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 288, elements: !32)
!32 = !{!33}
!33 = !DISubrange(count: 9, lowerBound: 0)
!34 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !35, size: 64, offset: 64)
!35 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !36, size: 64)
!36 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 4194304, elements: !37)
!37 = !{!38}
!38 = !DISubrange(count: 131072, lowerBound: 0)
!39 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !40, size: 64, offset: 128)
!40 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !41, size: 64)
!41 = !DICompositeType(tag: DW_TAG_array_type, baseType: !18, size: 96, elements: !42)
!42 = !{!43}
!43 = !DISubrange(count: 12, lowerBound: 0)
!44 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !45, size: 64, offset: 192)
!45 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !46, size: 64)
!46 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 8128, elements: !47)
!47 = !{!48}
!48 = !DISubrange(count: 127, lowerBound: 0)
!49 = !DIGlobalVariableExpression(var: !50, expr: !DIExpression())
!50 = distinct !DIGlobalVariable(name: "stack_bpftrace_6", linkageName: "global", scope: !2, file: !2, type: !51, isLocal: false, isDefinition: true)
!51 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !52)
!52 = !{!29, !34, !39, !53}
!53 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !54, size: 64, offset: 192)
!54 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !55, size: 64)
!55 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 384, elements: !56)
!56 = !{!57}
!57 = !DISubrange(count: 6, lowerBound: 0)
!58 = !DIGlobalVariableExpression(var: !59, expr: !DIExpression())
!59 = distinct !DIGlobalVariable(name: "stack_bpftrace_127", linkageName: "global", scope: !2, file: !2, type: !27, isLocal: false, isDefinition: true)
!60 = !DIGlobalVariableExpression(var: !61, expr: !DIExpression())
!61 = distinct !DIGlobalVariable(name: "stack_scratch", linkageName: "global", scope: !2, file: !2, type: !62, isLocal: false, isDefinition: true)
!62 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !63)
!63 = !{!64, !11, !67, !44}
!64 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !65, size: 64)
!65 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !66, size: 64)
!66 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 192, elements: !56)
!67 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !68, size: 64, offset: 128)
!68 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !69, size: 64)
!69 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!70 = !DIGlobalVariableExpression(var: !71, expr: !DIExpression())
!71 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !72, isLocal: false, isDefinition: true)
!72 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !73)
!73 = !{!74, !79}
!74 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !75, size: 64)
!75 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !76, size: 64)
!76 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !77)
!77 = !{!78}
!78 = !DISubrange(count: 27, lowerBound: 0)
!79 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !80, size: 64, offset: 64)
!80 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !81, size: 64)
!81 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !82)
!82 = !{!83}
!83 = !DISubrange(count: 262144, lowerBound: 0)
!84 = !DIGlobalVariableExpression(var: !85, expr: !DIExpression())
!85 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !86, isLocal: false, isDefinition: true)
!86 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !87)
!87 = !{!88, !11, !67, !93}
!88 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !89, size: 64)
!89 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !90, size: 64)
!90 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !91)
!91 = !{!92}
!92 = !DISubrange(count: 2, lowerBound: 0)
!93 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !13, size: 64, offset: 192)
!94 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !95)
!95 = !{!0, !21, !23, !25, !49, !58, !60, !70, !84}
!96 = !{i32 2, !"Debug Info Version", i32 3}
!97 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !98, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !94, retainedNodes: !101)
!98 = !DISubroutineType(types: !99)
!99 = !{!14, !100}
!100 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !18, size: 64)
!101 = !{!102}
!102 = !DILocalVariable(name: "ctx", arg: 1, scope: !97, file: !2, type: !100)
