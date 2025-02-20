; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr }
%"struct map_t.1" = type { ptr, ptr, ptr, ptr }
%helper_error_t = type <{ i64, i64, i32 }>

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_i = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@ringbuf = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !16
@event_loss_counter = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !30

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @BEGIN_1(ptr %0) section "s_BEGIN_1" !dbg !45 {
entry:
  %key109 = alloca i32, align 4
  %helper_error_t104 = alloca %helper_error_t, align 8
  %"@i_val100" = alloca i64, align 8
  %"@i_key99" = alloca i64, align 8
  %lookup_elem_val97 = alloca i64, align 8
  %"@i_key92" = alloca i64, align 8
  %key86 = alloca i32, align 4
  %helper_error_t81 = alloca %helper_error_t, align 8
  %"@i_val77" = alloca i64, align 8
  %"@i_key76" = alloca i64, align 8
  %lookup_elem_val74 = alloca i64, align 8
  %"@i_key69" = alloca i64, align 8
  %key63 = alloca i32, align 4
  %helper_error_t58 = alloca %helper_error_t, align 8
  %"@i_val54" = alloca i64, align 8
  %"@i_key53" = alloca i64, align 8
  %lookup_elem_val51 = alloca i64, align 8
  %"@i_key46" = alloca i64, align 8
  %key40 = alloca i32, align 4
  %helper_error_t35 = alloca %helper_error_t, align 8
  %"@i_val31" = alloca i64, align 8
  %"@i_key30" = alloca i64, align 8
  %lookup_elem_val28 = alloca i64, align 8
  %"@i_key23" = alloca i64, align 8
  %key17 = alloca i32, align 4
  %helper_error_t12 = alloca %helper_error_t, align 8
  %"@i_val8" = alloca i64, align 8
  %"@i_key7" = alloca i64, align 8
  %lookup_elem_val = alloca i64, align 8
  %"@i_key1" = alloca i64, align 8
  %key = alloca i32, align 4
  %helper_error_t = alloca %helper_error_t, align 8
  %"@i_val" = alloca i64, align 8
  %"@i_key" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_key")
  store i64 0, ptr %"@i_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_val")
  store i64 0, ptr %"@i_val", align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_i, ptr %"@i_key", ptr %"@i_val", i64 0)
  %1 = trunc i64 %update_elem to i32
  %2 = icmp sge i32 %1, 0
  br i1 %2, label %helper_merge, label %helper_failure

helper_failure:                                   ; preds = %entry
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t)
  %3 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 0
  store i64 30006, ptr %3, align 8
  %4 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 1
  store i64 0, ptr %4, align 8
  %5 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 2
  store i32 %1, ptr %5, align 4
  %ringbuf_output = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t, i64 20, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

helper_merge:                                     ; preds = %counter_merge, %entry
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_key1")
  store i64 0, ptr %"@i_key1", align 8
  %lookup_elem2 = call ptr inttoptr (i64 1 to ptr)(ptr @AT_i, ptr %"@i_key1")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_elem_val)
  %map_lookup_cond6 = icmp ne ptr %lookup_elem2, null
  br i1 %map_lookup_cond6, label %lookup_success3, label %lookup_failure4

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
  %6 = atomicrmw add ptr %lookup_elem, i64 1 seq_cst, align 8
  br label %lookup_merge

lookup_failure:                                   ; preds = %event_loss_counter
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key)
  br label %counter_merge

lookup_success3:                                  ; preds = %helper_merge
  %7 = load i64, ptr %lookup_elem2, align 8
  store i64 %7, ptr %lookup_elem_val, align 8
  br label %lookup_merge5

lookup_failure4:                                  ; preds = %helper_merge
  store i64 0, ptr %lookup_elem_val, align 8
  br label %lookup_merge5

lookup_merge5:                                    ; preds = %lookup_failure4, %lookup_success3
  %8 = load i64, ptr %lookup_elem_val, align 8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_elem_val)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_key1")
  %9 = add i64 %8, 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_key7")
  store i64 0, ptr %"@i_key7", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_val8")
  store i64 %9, ptr %"@i_val8", align 8
  %update_elem9 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_i, ptr %"@i_key7", ptr %"@i_val8", i64 0)
  %10 = trunc i64 %update_elem9 to i32
  %11 = icmp sge i32 %10, 0
  br i1 %11, label %helper_merge11, label %helper_failure10

helper_failure10:                                 ; preds = %lookup_merge5
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t12)
  %12 = getelementptr %helper_error_t, ptr %helper_error_t12, i64 0, i32 0
  store i64 30006, ptr %12, align 8
  %13 = getelementptr %helper_error_t, ptr %helper_error_t12, i64 0, i32 1
  store i64 1, ptr %13, align 8
  %14 = getelementptr %helper_error_t, ptr %helper_error_t12, i64 0, i32 2
  store i32 %10, ptr %14, align 4
  %ringbuf_output13 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t12, i64 20, i64 0)
  %ringbuf_loss16 = icmp slt i64 %ringbuf_output13, 0
  br i1 %ringbuf_loss16, label %event_loss_counter14, label %counter_merge15

helper_merge11:                                   ; preds = %counter_merge15, %lookup_merge5
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_val8")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_key7")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_key23")
  store i64 0, ptr %"@i_key23", align 8
  %lookup_elem24 = call ptr inttoptr (i64 1 to ptr)(ptr @AT_i, ptr %"@i_key23")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_elem_val28)
  %map_lookup_cond29 = icmp ne ptr %lookup_elem24, null
  br i1 %map_lookup_cond29, label %lookup_success25, label %lookup_failure26

event_loss_counter14:                             ; preds = %helper_failure10
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key17)
  store i32 0, ptr %key17, align 4
  %lookup_elem18 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key17)
  %map_lookup_cond22 = icmp ne ptr %lookup_elem18, null
  br i1 %map_lookup_cond22, label %lookup_success19, label %lookup_failure20

counter_merge15:                                  ; preds = %lookup_merge21, %helper_failure10
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t12)
  br label %helper_merge11

lookup_success19:                                 ; preds = %event_loss_counter14
  %15 = atomicrmw add ptr %lookup_elem18, i64 1 seq_cst, align 8
  br label %lookup_merge21

lookup_failure20:                                 ; preds = %event_loss_counter14
  br label %lookup_merge21

lookup_merge21:                                   ; preds = %lookup_failure20, %lookup_success19
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key17)
  br label %counter_merge15

lookup_success25:                                 ; preds = %helper_merge11
  %16 = load i64, ptr %lookup_elem24, align 8
  store i64 %16, ptr %lookup_elem_val28, align 8
  br label %lookup_merge27

lookup_failure26:                                 ; preds = %helper_merge11
  store i64 0, ptr %lookup_elem_val28, align 8
  br label %lookup_merge27

lookup_merge27:                                   ; preds = %lookup_failure26, %lookup_success25
  %17 = load i64, ptr %lookup_elem_val28, align 8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_elem_val28)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_key23")
  %18 = add i64 %17, 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_key30")
  store i64 0, ptr %"@i_key30", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_val31")
  store i64 %18, ptr %"@i_val31", align 8
  %update_elem32 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_i, ptr %"@i_key30", ptr %"@i_val31", i64 0)
  %19 = trunc i64 %update_elem32 to i32
  %20 = icmp sge i32 %19, 0
  br i1 %20, label %helper_merge34, label %helper_failure33

helper_failure33:                                 ; preds = %lookup_merge27
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t35)
  %21 = getelementptr %helper_error_t, ptr %helper_error_t35, i64 0, i32 0
  store i64 30006, ptr %21, align 8
  %22 = getelementptr %helper_error_t, ptr %helper_error_t35, i64 0, i32 1
  store i64 1, ptr %22, align 8
  %23 = getelementptr %helper_error_t, ptr %helper_error_t35, i64 0, i32 2
  store i32 %19, ptr %23, align 4
  %ringbuf_output36 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t35, i64 20, i64 0)
  %ringbuf_loss39 = icmp slt i64 %ringbuf_output36, 0
  br i1 %ringbuf_loss39, label %event_loss_counter37, label %counter_merge38

helper_merge34:                                   ; preds = %counter_merge38, %lookup_merge27
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_val31")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_key30")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_key46")
  store i64 0, ptr %"@i_key46", align 8
  %lookup_elem47 = call ptr inttoptr (i64 1 to ptr)(ptr @AT_i, ptr %"@i_key46")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_elem_val51)
  %map_lookup_cond52 = icmp ne ptr %lookup_elem47, null
  br i1 %map_lookup_cond52, label %lookup_success48, label %lookup_failure49

event_loss_counter37:                             ; preds = %helper_failure33
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key40)
  store i32 0, ptr %key40, align 4
  %lookup_elem41 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key40)
  %map_lookup_cond45 = icmp ne ptr %lookup_elem41, null
  br i1 %map_lookup_cond45, label %lookup_success42, label %lookup_failure43

counter_merge38:                                  ; preds = %lookup_merge44, %helper_failure33
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t35)
  br label %helper_merge34

lookup_success42:                                 ; preds = %event_loss_counter37
  %24 = atomicrmw add ptr %lookup_elem41, i64 1 seq_cst, align 8
  br label %lookup_merge44

lookup_failure43:                                 ; preds = %event_loss_counter37
  br label %lookup_merge44

lookup_merge44:                                   ; preds = %lookup_failure43, %lookup_success42
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key40)
  br label %counter_merge38

lookup_success48:                                 ; preds = %helper_merge34
  %25 = load i64, ptr %lookup_elem47, align 8
  store i64 %25, ptr %lookup_elem_val51, align 8
  br label %lookup_merge50

lookup_failure49:                                 ; preds = %helper_merge34
  store i64 0, ptr %lookup_elem_val51, align 8
  br label %lookup_merge50

lookup_merge50:                                   ; preds = %lookup_failure49, %lookup_success48
  %26 = load i64, ptr %lookup_elem_val51, align 8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_elem_val51)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_key46")
  %27 = add i64 %26, 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_key53")
  store i64 0, ptr %"@i_key53", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_val54")
  store i64 %27, ptr %"@i_val54", align 8
  %update_elem55 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_i, ptr %"@i_key53", ptr %"@i_val54", i64 0)
  %28 = trunc i64 %update_elem55 to i32
  %29 = icmp sge i32 %28, 0
  br i1 %29, label %helper_merge57, label %helper_failure56

helper_failure56:                                 ; preds = %lookup_merge50
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t58)
  %30 = getelementptr %helper_error_t, ptr %helper_error_t58, i64 0, i32 0
  store i64 30006, ptr %30, align 8
  %31 = getelementptr %helper_error_t, ptr %helper_error_t58, i64 0, i32 1
  store i64 1, ptr %31, align 8
  %32 = getelementptr %helper_error_t, ptr %helper_error_t58, i64 0, i32 2
  store i32 %28, ptr %32, align 4
  %ringbuf_output59 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t58, i64 20, i64 0)
  %ringbuf_loss62 = icmp slt i64 %ringbuf_output59, 0
  br i1 %ringbuf_loss62, label %event_loss_counter60, label %counter_merge61

helper_merge57:                                   ; preds = %counter_merge61, %lookup_merge50
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_val54")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_key53")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_key69")
  store i64 0, ptr %"@i_key69", align 8
  %lookup_elem70 = call ptr inttoptr (i64 1 to ptr)(ptr @AT_i, ptr %"@i_key69")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_elem_val74)
  %map_lookup_cond75 = icmp ne ptr %lookup_elem70, null
  br i1 %map_lookup_cond75, label %lookup_success71, label %lookup_failure72

event_loss_counter60:                             ; preds = %helper_failure56
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key63)
  store i32 0, ptr %key63, align 4
  %lookup_elem64 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key63)
  %map_lookup_cond68 = icmp ne ptr %lookup_elem64, null
  br i1 %map_lookup_cond68, label %lookup_success65, label %lookup_failure66

counter_merge61:                                  ; preds = %lookup_merge67, %helper_failure56
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t58)
  br label %helper_merge57

lookup_success65:                                 ; preds = %event_loss_counter60
  %33 = atomicrmw add ptr %lookup_elem64, i64 1 seq_cst, align 8
  br label %lookup_merge67

lookup_failure66:                                 ; preds = %event_loss_counter60
  br label %lookup_merge67

lookup_merge67:                                   ; preds = %lookup_failure66, %lookup_success65
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key63)
  br label %counter_merge61

lookup_success71:                                 ; preds = %helper_merge57
  %34 = load i64, ptr %lookup_elem70, align 8
  store i64 %34, ptr %lookup_elem_val74, align 8
  br label %lookup_merge73

lookup_failure72:                                 ; preds = %helper_merge57
  store i64 0, ptr %lookup_elem_val74, align 8
  br label %lookup_merge73

lookup_merge73:                                   ; preds = %lookup_failure72, %lookup_success71
  %35 = load i64, ptr %lookup_elem_val74, align 8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_elem_val74)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_key69")
  %36 = add i64 %35, 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_key76")
  store i64 0, ptr %"@i_key76", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_val77")
  store i64 %36, ptr %"@i_val77", align 8
  %update_elem78 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_i, ptr %"@i_key76", ptr %"@i_val77", i64 0)
  %37 = trunc i64 %update_elem78 to i32
  %38 = icmp sge i32 %37, 0
  br i1 %38, label %helper_merge80, label %helper_failure79

helper_failure79:                                 ; preds = %lookup_merge73
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t81)
  %39 = getelementptr %helper_error_t, ptr %helper_error_t81, i64 0, i32 0
  store i64 30006, ptr %39, align 8
  %40 = getelementptr %helper_error_t, ptr %helper_error_t81, i64 0, i32 1
  store i64 1, ptr %40, align 8
  %41 = getelementptr %helper_error_t, ptr %helper_error_t81, i64 0, i32 2
  store i32 %37, ptr %41, align 4
  %ringbuf_output82 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t81, i64 20, i64 0)
  %ringbuf_loss85 = icmp slt i64 %ringbuf_output82, 0
  br i1 %ringbuf_loss85, label %event_loss_counter83, label %counter_merge84

helper_merge80:                                   ; preds = %counter_merge84, %lookup_merge73
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_val77")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_key76")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_key92")
  store i64 0, ptr %"@i_key92", align 8
  %lookup_elem93 = call ptr inttoptr (i64 1 to ptr)(ptr @AT_i, ptr %"@i_key92")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_elem_val97)
  %map_lookup_cond98 = icmp ne ptr %lookup_elem93, null
  br i1 %map_lookup_cond98, label %lookup_success94, label %lookup_failure95

event_loss_counter83:                             ; preds = %helper_failure79
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key86)
  store i32 0, ptr %key86, align 4
  %lookup_elem87 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key86)
  %map_lookup_cond91 = icmp ne ptr %lookup_elem87, null
  br i1 %map_lookup_cond91, label %lookup_success88, label %lookup_failure89

counter_merge84:                                  ; preds = %lookup_merge90, %helper_failure79
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t81)
  br label %helper_merge80

lookup_success88:                                 ; preds = %event_loss_counter83
  %42 = atomicrmw add ptr %lookup_elem87, i64 1 seq_cst, align 8
  br label %lookup_merge90

lookup_failure89:                                 ; preds = %event_loss_counter83
  br label %lookup_merge90

lookup_merge90:                                   ; preds = %lookup_failure89, %lookup_success88
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key86)
  br label %counter_merge84

lookup_success94:                                 ; preds = %helper_merge80
  %43 = load i64, ptr %lookup_elem93, align 8
  store i64 %43, ptr %lookup_elem_val97, align 8
  br label %lookup_merge96

lookup_failure95:                                 ; preds = %helper_merge80
  store i64 0, ptr %lookup_elem_val97, align 8
  br label %lookup_merge96

lookup_merge96:                                   ; preds = %lookup_failure95, %lookup_success94
  %44 = load i64, ptr %lookup_elem_val97, align 8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_elem_val97)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_key92")
  %45 = add i64 %44, 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_key99")
  store i64 0, ptr %"@i_key99", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@i_val100")
  store i64 %45, ptr %"@i_val100", align 8
  %update_elem101 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_i, ptr %"@i_key99", ptr %"@i_val100", i64 0)
  %46 = trunc i64 %update_elem101 to i32
  %47 = icmp sge i32 %46, 0
  br i1 %47, label %helper_merge103, label %helper_failure102

helper_failure102:                                ; preds = %lookup_merge96
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t104)
  %48 = getelementptr %helper_error_t, ptr %helper_error_t104, i64 0, i32 0
  store i64 30006, ptr %48, align 8
  %49 = getelementptr %helper_error_t, ptr %helper_error_t104, i64 0, i32 1
  store i64 1, ptr %49, align 8
  %50 = getelementptr %helper_error_t, ptr %helper_error_t104, i64 0, i32 2
  store i32 %46, ptr %50, align 4
  %ringbuf_output105 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t104, i64 20, i64 0)
  %ringbuf_loss108 = icmp slt i64 %ringbuf_output105, 0
  br i1 %ringbuf_loss108, label %event_loss_counter106, label %counter_merge107

helper_merge103:                                  ; preds = %counter_merge107, %lookup_merge96
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_val100")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@i_key99")
  ret i64 0

event_loss_counter106:                            ; preds = %helper_failure102
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key109)
  store i32 0, ptr %key109, align 4
  %lookup_elem110 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key109)
  %map_lookup_cond114 = icmp ne ptr %lookup_elem110, null
  br i1 %map_lookup_cond114, label %lookup_success111, label %lookup_failure112

counter_merge107:                                 ; preds = %lookup_merge113, %helper_failure102
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t104)
  br label %helper_merge103

lookup_success111:                                ; preds = %event_loss_counter106
  %51 = atomicrmw add ptr %lookup_elem110, i64 1 seq_cst, align 8
  br label %lookup_merge113

lookup_failure112:                                ; preds = %event_loss_counter106
  br label %lookup_merge113

lookup_merge113:                                  ; preds = %lookup_failure112, %lookup_success111
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key109)
  br label %counter_merge107
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }

!llvm.dbg.cu = !{!42}
!llvm.module.flags = !{!44}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "AT_i", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
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
!15 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !13, size: 64, offset: 192)
!16 = !DIGlobalVariableExpression(var: !17, expr: !DIExpression())
!17 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !18, isLocal: false, isDefinition: true)
!18 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !19)
!19 = !{!20, !25}
!20 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !21, size: 64)
!21 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !22, size: 64)
!22 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !23)
!23 = !{!24}
!24 = !DISubrange(count: 27, lowerBound: 0)
!25 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !26, size: 64, offset: 64)
!26 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !27, size: 64)
!27 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !28)
!28 = !{!29}
!29 = !DISubrange(count: 262144, lowerBound: 0)
!30 = !DIGlobalVariableExpression(var: !31, expr: !DIExpression())
!31 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !32, isLocal: false, isDefinition: true)
!32 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !33)
!33 = !{!34, !11, !39, !15}
!34 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !35, size: 64)
!35 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !36, size: 64)
!36 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !37)
!37 = !{!38}
!38 = !DISubrange(count: 2, lowerBound: 0)
!39 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !40, size: 64, offset: 128)
!40 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !41, size: 64)
!41 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!42 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !43)
!43 = !{!0, !16, !30}
!44 = !{i32 2, !"Debug Info Version", i32 3}
!45 = distinct !DISubprogram(name: "BEGIN_1", linkageName: "BEGIN_1", scope: !2, file: !2, type: !46, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !42, retainedNodes: !50)
!46 = !DISubroutineType(types: !47)
!47 = !{!14, !48}
!48 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !49, size: 64)
!49 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!50 = !{!51}
!51 = !DILocalVariable(name: "ctx", arg: 1, scope: !45, file: !2, type: !48)
