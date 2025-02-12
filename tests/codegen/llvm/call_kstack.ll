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
%kstack_key = type { i64, i32 }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_x = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@AT_y = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !21
@AT_z = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !23
@stack_perf_127 = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !25
@stack_bpftrace_6 = dso_local global %"struct map_t.3" zeroinitializer, section ".maps", !dbg !45
@stack_bpftrace_127 = dso_local global %"struct map_t.4" zeroinitializer, section ".maps", !dbg !54
@stack_scratch = dso_local global %"struct map_t.5" zeroinitializer, section ".maps", !dbg !56
@ringbuf = dso_local global %"struct map_t.6" zeroinitializer, section ".maps", !dbg !66
@event_loss_counter = dso_local global %"struct map_t.7" zeroinitializer, section ".maps", !dbg !80

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(ptr %0) section "s_kprobe_f_1" !dbg !93 {
entry:
  %key129 = alloca i32, align 4
  %helper_error_t124 = alloca %helper_error_t, align 8
  %"@z_key" = alloca i64, align 8
  %key115 = alloca i32, align 4
  %helper_error_t110 = alloca %helper_error_t, align 8
  %key100 = alloca i32, align 4
  %helper_error_t95 = alloca %helper_error_t, align 8
  %lookup_stack_scratch_key84 = alloca i32, align 4
  %stack_key81 = alloca %kstack_key, align 8
  %key75 = alloca i32, align 4
  %helper_error_t70 = alloca %helper_error_t, align 8
  %"@y_key" = alloca i64, align 8
  %key61 = alloca i32, align 4
  %helper_error_t56 = alloca %helper_error_t, align 8
  %key46 = alloca i32, align 4
  %helper_error_t41 = alloca %helper_error_t, align 8
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
  call void @llvm.lifetime.start.p0(i64 -1, ptr %stack_key28)
  %24 = getelementptr %kstack_key, ptr %stack_key28, i64 0, i32 0
  store i64 0, ptr %24, align 8
  %25 = getelementptr %kstack_key, ptr %stack_key28, i64 0, i32 1
  store i32 0, ptr %25, align 4
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

merge_block30:                                    ; preds = %stack_scratch_failure29, %helper_merge55, %get_stack_fail37
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@y_key")
  store i64 0, ptr %"@y_key", align 8
  %update_elem67 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_y, ptr %"@y_key", ptr %stack_key28, i64 0)
  %27 = trunc i64 %update_elem67 to i32
  %28 = icmp sge i32 %27, 0
  br i1 %28, label %helper_merge69, label %helper_failure68

lookup_stack_scratch_failure33:                   ; preds = %helper_merge16
  br label %stack_scratch_failure29

lookup_stack_scratch_merge34:                     ; preds = %helper_merge16
  call void @llvm.memset.p0.i64(ptr align 1 %lookup_stack_scratch_map32, i8 0, i64 48, i1 false)
  %get_stack38 = call i32 inttoptr (i64 67 to ptr)(ptr %0, ptr %lookup_stack_scratch_map32, i32 48, i64 0)
  %29 = icmp sge i32 %get_stack38, 0
  br i1 %29, label %helper_merge40, label %helper_failure39

get_stack_success36:                              ; preds = %helper_merge40
  %30 = udiv i32 %get_stack38, 8
  %31 = getelementptr %kstack_key, ptr %stack_key28, i64 0, i32 1
  store i32 %30, ptr %31, align 4
  %32 = trunc i32 %30 to i8
  %murmur_hash_252 = call i64 @murmur_hash_2(ptr %lookup_stack_scratch_map32, i8 %32, i64 1)
  %33 = getelementptr %kstack_key, ptr %stack_key28, i64 0, i32 0
  store i64 %murmur_hash_252, ptr %33, align 8
  %update_elem53 = call i64 inttoptr (i64 2 to ptr)(ptr @stack_bpftrace_6, ptr %stack_key28, ptr %lookup_stack_scratch_map32, i64 0)
  %34 = trunc i64 %update_elem53 to i32
  %35 = icmp sge i32 %34, 0
  br i1 %35, label %helper_merge55, label %helper_failure54

get_stack_fail37:                                 ; preds = %helper_merge40
  br label %merge_block30

helper_failure39:                                 ; preds = %lookup_stack_scratch_merge34
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t41)
  %36 = getelementptr %helper_error_t, ptr %helper_error_t41, i64 0, i32 0
  store i64 30006, ptr %36, align 8
  %37 = getelementptr %helper_error_t, ptr %helper_error_t41, i64 0, i32 1
  store i64 3, ptr %37, align 8
  %38 = getelementptr %helper_error_t, ptr %helper_error_t41, i64 0, i32 2
  store i32 %get_stack38, ptr %38, align 4
  %ringbuf_output42 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t41, i64 20, i64 0)
  %ringbuf_loss45 = icmp slt i64 %ringbuf_output42, 0
  br i1 %ringbuf_loss45, label %event_loss_counter43, label %counter_merge44

helper_merge40:                                   ; preds = %counter_merge44, %lookup_stack_scratch_merge34
  %39 = icmp sge i32 %get_stack38, 0
  br i1 %39, label %get_stack_success36, label %get_stack_fail37

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
  %40 = atomicrmw add ptr %lookup_elem47, i64 1 seq_cst, align 8
  br label %lookup_merge50

lookup_failure49:                                 ; preds = %event_loss_counter43
  br label %lookup_merge50

lookup_merge50:                                   ; preds = %lookup_failure49, %lookup_success48
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key46)
  br label %counter_merge44

helper_failure54:                                 ; preds = %get_stack_success36
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t56)
  %41 = getelementptr %helper_error_t, ptr %helper_error_t56, i64 0, i32 0
  store i64 30006, ptr %41, align 8
  %42 = getelementptr %helper_error_t, ptr %helper_error_t56, i64 0, i32 1
  store i64 4, ptr %42, align 8
  %43 = getelementptr %helper_error_t, ptr %helper_error_t56, i64 0, i32 2
  store i32 %34, ptr %43, align 4
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
  %44 = atomicrmw add ptr %lookup_elem62, i64 1 seq_cst, align 8
  br label %lookup_merge65

lookup_failure64:                                 ; preds = %event_loss_counter58
  br label %lookup_merge65

lookup_merge65:                                   ; preds = %lookup_failure64, %lookup_success63
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key61)
  br label %counter_merge59

helper_failure68:                                 ; preds = %merge_block30
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t70)
  %45 = getelementptr %helper_error_t, ptr %helper_error_t70, i64 0, i32 0
  store i64 30006, ptr %45, align 8
  %46 = getelementptr %helper_error_t, ptr %helper_error_t70, i64 0, i32 1
  store i64 5, ptr %46, align 8
  %47 = getelementptr %helper_error_t, ptr %helper_error_t70, i64 0, i32 2
  store i32 %27, ptr %47, align 4
  %ringbuf_output71 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t70, i64 20, i64 0)
  %ringbuf_loss74 = icmp slt i64 %ringbuf_output71, 0
  br i1 %ringbuf_loss74, label %event_loss_counter72, label %counter_merge73

helper_merge69:                                   ; preds = %counter_merge73, %merge_block30
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@y_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %stack_key81)
  %48 = getelementptr %kstack_key, ptr %stack_key81, i64 0, i32 0
  store i64 0, ptr %48, align 8
  %49 = getelementptr %kstack_key, ptr %stack_key81, i64 0, i32 1
  store i32 0, ptr %49, align 4
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_stack_scratch_key84)
  store i32 0, ptr %lookup_stack_scratch_key84, align 4
  %lookup_stack_scratch_map85 = call ptr inttoptr (i64 1 to ptr)(ptr @stack_scratch, ptr %lookup_stack_scratch_key84)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_stack_scratch_key84)
  %lookup_stack_scratch_cond88 = icmp ne ptr %lookup_stack_scratch_map85, null
  br i1 %lookup_stack_scratch_cond88, label %lookup_stack_scratch_merge87, label %lookup_stack_scratch_failure86

event_loss_counter72:                             ; preds = %helper_failure68
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key75)
  store i32 0, ptr %key75, align 4
  %lookup_elem76 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key75)
  %map_lookup_cond80 = icmp ne ptr %lookup_elem76, null
  br i1 %map_lookup_cond80, label %lookup_success77, label %lookup_failure78

counter_merge73:                                  ; preds = %lookup_merge79, %helper_failure68
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t70)
  br label %helper_merge69

lookup_success77:                                 ; preds = %event_loss_counter72
  %50 = atomicrmw add ptr %lookup_elem76, i64 1 seq_cst, align 8
  br label %lookup_merge79

lookup_failure78:                                 ; preds = %event_loss_counter72
  br label %lookup_merge79

lookup_merge79:                                   ; preds = %lookup_failure78, %lookup_success77
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key75)
  br label %counter_merge73

stack_scratch_failure82:                          ; preds = %lookup_stack_scratch_failure86
  br label %merge_block83

merge_block83:                                    ; preds = %stack_scratch_failure82, %helper_merge109, %get_stack_fail91
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@z_key")
  store i64 0, ptr %"@z_key", align 8
  %update_elem121 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_z, ptr %"@z_key", ptr %stack_key81, i64 0)
  %51 = trunc i64 %update_elem121 to i32
  %52 = icmp sge i32 %51, 0
  br i1 %52, label %helper_merge123, label %helper_failure122

lookup_stack_scratch_failure86:                   ; preds = %helper_merge69
  br label %stack_scratch_failure82

lookup_stack_scratch_merge87:                     ; preds = %helper_merge69
  %probe_read_kernel89 = call i64 inttoptr (i64 113 to ptr)(ptr %lookup_stack_scratch_map85, i32 1016, ptr null)
  %get_stack92 = call i32 inttoptr (i64 67 to ptr)(ptr %0, ptr %lookup_stack_scratch_map85, i32 1016, i64 0)
  %53 = icmp sge i32 %get_stack92, 0
  br i1 %53, label %helper_merge94, label %helper_failure93

get_stack_success90:                              ; preds = %helper_merge94
  %54 = udiv i32 %get_stack92, 8
  %55 = getelementptr %kstack_key, ptr %stack_key81, i64 0, i32 1
  store i32 %54, ptr %55, align 4
  %56 = trunc i32 %54 to i8
  %murmur_hash_2106 = call i64 @murmur_hash_2(ptr %lookup_stack_scratch_map85, i8 %56, i64 1)
  %57 = getelementptr %kstack_key, ptr %stack_key81, i64 0, i32 0
  store i64 %murmur_hash_2106, ptr %57, align 8
  %update_elem107 = call i64 inttoptr (i64 2 to ptr)(ptr @stack_perf_127, ptr %stack_key81, ptr %lookup_stack_scratch_map85, i64 0)
  %58 = trunc i64 %update_elem107 to i32
  %59 = icmp sge i32 %58, 0
  br i1 %59, label %helper_merge109, label %helper_failure108

get_stack_fail91:                                 ; preds = %helper_merge94
  br label %merge_block83

helper_failure93:                                 ; preds = %lookup_stack_scratch_merge87
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t95)
  %60 = getelementptr %helper_error_t, ptr %helper_error_t95, i64 0, i32 0
  store i64 30006, ptr %60, align 8
  %61 = getelementptr %helper_error_t, ptr %helper_error_t95, i64 0, i32 1
  store i64 6, ptr %61, align 8
  %62 = getelementptr %helper_error_t, ptr %helper_error_t95, i64 0, i32 2
  store i32 %get_stack92, ptr %62, align 4
  %ringbuf_output96 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t95, i64 20, i64 0)
  %ringbuf_loss99 = icmp slt i64 %ringbuf_output96, 0
  br i1 %ringbuf_loss99, label %event_loss_counter97, label %counter_merge98

helper_merge94:                                   ; preds = %counter_merge98, %lookup_stack_scratch_merge87
  %63 = icmp sge i32 %get_stack92, 0
  br i1 %63, label %get_stack_success90, label %get_stack_fail91

event_loss_counter97:                             ; preds = %helper_failure93
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key100)
  store i32 0, ptr %key100, align 4
  %lookup_elem101 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key100)
  %map_lookup_cond105 = icmp ne ptr %lookup_elem101, null
  br i1 %map_lookup_cond105, label %lookup_success102, label %lookup_failure103

counter_merge98:                                  ; preds = %lookup_merge104, %helper_failure93
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t95)
  br label %helper_merge94

lookup_success102:                                ; preds = %event_loss_counter97
  %64 = atomicrmw add ptr %lookup_elem101, i64 1 seq_cst, align 8
  br label %lookup_merge104

lookup_failure103:                                ; preds = %event_loss_counter97
  br label %lookup_merge104

lookup_merge104:                                  ; preds = %lookup_failure103, %lookup_success102
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key100)
  br label %counter_merge98

helper_failure108:                                ; preds = %get_stack_success90
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t110)
  %65 = getelementptr %helper_error_t, ptr %helper_error_t110, i64 0, i32 0
  store i64 30006, ptr %65, align 8
  %66 = getelementptr %helper_error_t, ptr %helper_error_t110, i64 0, i32 1
  store i64 7, ptr %66, align 8
  %67 = getelementptr %helper_error_t, ptr %helper_error_t110, i64 0, i32 2
  store i32 %58, ptr %67, align 4
  %ringbuf_output111 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t110, i64 20, i64 0)
  %ringbuf_loss114 = icmp slt i64 %ringbuf_output111, 0
  br i1 %ringbuf_loss114, label %event_loss_counter112, label %counter_merge113

helper_merge109:                                  ; preds = %counter_merge113, %get_stack_success90
  br label %merge_block83

event_loss_counter112:                            ; preds = %helper_failure108
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key115)
  store i32 0, ptr %key115, align 4
  %lookup_elem116 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key115)
  %map_lookup_cond120 = icmp ne ptr %lookup_elem116, null
  br i1 %map_lookup_cond120, label %lookup_success117, label %lookup_failure118

counter_merge113:                                 ; preds = %lookup_merge119, %helper_failure108
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t110)
  br label %helper_merge109

lookup_success117:                                ; preds = %event_loss_counter112
  %68 = atomicrmw add ptr %lookup_elem116, i64 1 seq_cst, align 8
  br label %lookup_merge119

lookup_failure118:                                ; preds = %event_loss_counter112
  br label %lookup_merge119

lookup_merge119:                                  ; preds = %lookup_failure118, %lookup_success117
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key115)
  br label %counter_merge113

helper_failure122:                                ; preds = %merge_block83
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t124)
  %69 = getelementptr %helper_error_t, ptr %helper_error_t124, i64 0, i32 0
  store i64 30006, ptr %69, align 8
  %70 = getelementptr %helper_error_t, ptr %helper_error_t124, i64 0, i32 1
  store i64 8, ptr %70, align 8
  %71 = getelementptr %helper_error_t, ptr %helper_error_t124, i64 0, i32 2
  store i32 %51, ptr %71, align 4
  %ringbuf_output125 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t124, i64 20, i64 0)
  %ringbuf_loss128 = icmp slt i64 %ringbuf_output125, 0
  br i1 %ringbuf_loss128, label %event_loss_counter126, label %counter_merge127

helper_merge123:                                  ; preds = %counter_merge127, %merge_block83
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@z_key")
  ret i64 0

event_loss_counter126:                            ; preds = %helper_failure122
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key129)
  store i32 0, ptr %key129, align 4
  %lookup_elem130 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key129)
  %map_lookup_cond134 = icmp ne ptr %lookup_elem130, null
  br i1 %map_lookup_cond134, label %lookup_success131, label %lookup_failure132

counter_merge127:                                 ; preds = %lookup_merge133, %helper_failure122
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t124)
  br label %helper_merge123

lookup_success131:                                ; preds = %event_loss_counter126
  %72 = atomicrmw add ptr %lookup_elem130, i64 1 seq_cst, align 8
  br label %lookup_merge133

lookup_failure132:                                ; preds = %event_loss_counter126
  br label %lookup_merge133

lookup_merge133:                                  ; preds = %lookup_failure132, %lookup_success131
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key129)
  br label %counter_merge127
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
!17 = !DICompositeType(tag: DW_TAG_array_type, baseType: !18, size: 96, elements: !19)
!18 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!19 = !{!20}
!20 = !DISubrange(count: 12, lowerBound: 0)
!21 = !DIGlobalVariableExpression(var: !22, expr: !DIExpression())
!22 = distinct !DIGlobalVariable(name: "AT_y", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!23 = !DIGlobalVariableExpression(var: !24, expr: !DIExpression())
!24 = distinct !DIGlobalVariable(name: "AT_z", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!25 = !DIGlobalVariableExpression(var: !26, expr: !DIExpression())
!26 = distinct !DIGlobalVariable(name: "stack_perf_127", linkageName: "global", scope: !2, file: !2, type: !27, isLocal: false, isDefinition: true)
!27 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !28)
!28 = !{!29, !34, !39, !40}
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
!39 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !16, size: 64, offset: 128)
!40 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !41, size: 64, offset: 192)
!41 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !42, size: 64)
!42 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 8128, elements: !43)
!43 = !{!44}
!44 = !DISubrange(count: 127, lowerBound: 0)
!45 = !DIGlobalVariableExpression(var: !46, expr: !DIExpression())
!46 = distinct !DIGlobalVariable(name: "stack_bpftrace_6", linkageName: "global", scope: !2, file: !2, type: !47, isLocal: false, isDefinition: true)
!47 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !48)
!48 = !{!29, !34, !39, !49}
!49 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !50, size: 64, offset: 192)
!50 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !51, size: 64)
!51 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 384, elements: !52)
!52 = !{!53}
!53 = !DISubrange(count: 6, lowerBound: 0)
!54 = !DIGlobalVariableExpression(var: !55, expr: !DIExpression())
!55 = distinct !DIGlobalVariable(name: "stack_bpftrace_127", linkageName: "global", scope: !2, file: !2, type: !27, isLocal: false, isDefinition: true)
!56 = !DIGlobalVariableExpression(var: !57, expr: !DIExpression())
!57 = distinct !DIGlobalVariable(name: "stack_scratch", linkageName: "global", scope: !2, file: !2, type: !58, isLocal: false, isDefinition: true)
!58 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !59)
!59 = !{!60, !11, !63, !40}
!60 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !61, size: 64)
!61 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !62, size: 64)
!62 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 192, elements: !52)
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
!91 = !{!0, !21, !23, !25, !45, !54, !56, !66, !80}
!92 = !{i32 2, !"Debug Info Version", i32 3}
!93 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !94, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !90, retainedNodes: !97)
!94 = !DISubroutineType(types: !95)
!95 = !{!14, !96}
!96 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !18, size: 64)
!97 = !{!98}
!98 = !DILocalVariable(name: "ctx", arg: 1, scope: !93, file: !2, type: !96)
