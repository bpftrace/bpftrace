; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr }
%"struct map_t.1" = type { ptr, ptr, ptr, ptr }
%helper_error_t = type <{ i64, i64, i32 }>

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_x = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@ringbuf = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !16
@event_loss_counter = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !30

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @BEGIN_1(ptr %0) section "s_BEGIN_1" !dbg !45 {
entry:
  %key81 = alloca i32, align 4
  %helper_error_t76 = alloca %helper_error_t, align 8
  %"@x_newval72" = alloca i64, align 8
  %lookup_elem_val70 = alloca i64, align 8
  %"@x_key65" = alloca i64, align 8
  %key59 = alloca i32, align 4
  %helper_error_t54 = alloca %helper_error_t, align 8
  %"@x_newval50" = alloca i64, align 8
  %lookup_elem_val48 = alloca i64, align 8
  %"@x_key43" = alloca i64, align 8
  %key37 = alloca i32, align 4
  %helper_error_t32 = alloca %helper_error_t, align 8
  %"@x_newval28" = alloca i64, align 8
  %lookup_elem_val26 = alloca i64, align 8
  %"@x_key21" = alloca i64, align 8
  %key15 = alloca i32, align 4
  %helper_error_t10 = alloca %helper_error_t, align 8
  %"@x_newval" = alloca i64, align 8
  %lookup_elem_val = alloca i64, align 8
  %"@x_key1" = alloca i64, align 8
  %key = alloca i32, align 4
  %helper_error_t = alloca %helper_error_t, align 8
  %"@x_val" = alloca i64, align 8
  %"@x_key" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key")
  store i64 0, ptr %"@x_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_val")
  store i64 10, ptr %"@x_val", align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %"@x_key", ptr %"@x_val", i64 0)
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
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key1")
  store i64 0, ptr %"@x_key1", align 8
  %lookup_elem2 = call ptr inttoptr (i64 1 to ptr)(ptr @AT_x, ptr %"@x_key1")
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
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_newval")
  %9 = add i64 %8, 1
  store i64 %9, ptr %"@x_newval", align 8
  %update_elem7 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %"@x_key1", ptr %"@x_newval", i64 0)
  %10 = trunc i64 %update_elem7 to i32
  %11 = icmp sge i32 %10, 0
  br i1 %11, label %helper_merge9, label %helper_failure8

helper_failure8:                                  ; preds = %lookup_merge5
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t10)
  %12 = getelementptr %helper_error_t, ptr %helper_error_t10, i64 0, i32 0
  store i64 30006, ptr %12, align 8
  %13 = getelementptr %helper_error_t, ptr %helper_error_t10, i64 0, i32 1
  store i64 1, ptr %13, align 8
  %14 = getelementptr %helper_error_t, ptr %helper_error_t10, i64 0, i32 2
  store i32 %10, ptr %14, align 4
  %ringbuf_output11 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t10, i64 20, i64 0)
  %ringbuf_loss14 = icmp slt i64 %ringbuf_output11, 0
  br i1 %ringbuf_loss14, label %event_loss_counter12, label %counter_merge13

helper_merge9:                                    ; preds = %counter_merge13, %lookup_merge5
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_newval")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key1")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key21")
  store i64 0, ptr %"@x_key21", align 8
  %lookup_elem22 = call ptr inttoptr (i64 1 to ptr)(ptr @AT_x, ptr %"@x_key21")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_elem_val26)
  %map_lookup_cond27 = icmp ne ptr %lookup_elem22, null
  br i1 %map_lookup_cond27, label %lookup_success23, label %lookup_failure24

event_loss_counter12:                             ; preds = %helper_failure8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key15)
  store i32 0, ptr %key15, align 4
  %lookup_elem16 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key15)
  %map_lookup_cond20 = icmp ne ptr %lookup_elem16, null
  br i1 %map_lookup_cond20, label %lookup_success17, label %lookup_failure18

counter_merge13:                                  ; preds = %lookup_merge19, %helper_failure8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t10)
  br label %helper_merge9

lookup_success17:                                 ; preds = %event_loss_counter12
  %15 = atomicrmw add ptr %lookup_elem16, i64 1 seq_cst, align 8
  br label %lookup_merge19

lookup_failure18:                                 ; preds = %event_loss_counter12
  br label %lookup_merge19

lookup_merge19:                                   ; preds = %lookup_failure18, %lookup_success17
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key15)
  br label %counter_merge13

lookup_success23:                                 ; preds = %helper_merge9
  %16 = load i64, ptr %lookup_elem22, align 8
  store i64 %16, ptr %lookup_elem_val26, align 8
  br label %lookup_merge25

lookup_failure24:                                 ; preds = %helper_merge9
  store i64 0, ptr %lookup_elem_val26, align 8
  br label %lookup_merge25

lookup_merge25:                                   ; preds = %lookup_failure24, %lookup_success23
  %17 = load i64, ptr %lookup_elem_val26, align 8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_elem_val26)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_newval28")
  %18 = add i64 %17, 1
  store i64 %18, ptr %"@x_newval28", align 8
  %update_elem29 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %"@x_key21", ptr %"@x_newval28", i64 0)
  %19 = trunc i64 %update_elem29 to i32
  %20 = icmp sge i32 %19, 0
  br i1 %20, label %helper_merge31, label %helper_failure30

helper_failure30:                                 ; preds = %lookup_merge25
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t32)
  %21 = getelementptr %helper_error_t, ptr %helper_error_t32, i64 0, i32 0
  store i64 30006, ptr %21, align 8
  %22 = getelementptr %helper_error_t, ptr %helper_error_t32, i64 0, i32 1
  store i64 2, ptr %22, align 8
  %23 = getelementptr %helper_error_t, ptr %helper_error_t32, i64 0, i32 2
  store i32 %19, ptr %23, align 4
  %ringbuf_output33 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t32, i64 20, i64 0)
  %ringbuf_loss36 = icmp slt i64 %ringbuf_output33, 0
  br i1 %ringbuf_loss36, label %event_loss_counter34, label %counter_merge35

helper_merge31:                                   ; preds = %counter_merge35, %lookup_merge25
  %24 = load i64, ptr %"@x_newval28", align 8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_newval28")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key21")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key43")
  store i64 0, ptr %"@x_key43", align 8
  %lookup_elem44 = call ptr inttoptr (i64 1 to ptr)(ptr @AT_x, ptr %"@x_key43")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_elem_val48)
  %map_lookup_cond49 = icmp ne ptr %lookup_elem44, null
  br i1 %map_lookup_cond49, label %lookup_success45, label %lookup_failure46

event_loss_counter34:                             ; preds = %helper_failure30
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key37)
  store i32 0, ptr %key37, align 4
  %lookup_elem38 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key37)
  %map_lookup_cond42 = icmp ne ptr %lookup_elem38, null
  br i1 %map_lookup_cond42, label %lookup_success39, label %lookup_failure40

counter_merge35:                                  ; preds = %lookup_merge41, %helper_failure30
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t32)
  br label %helper_merge31

lookup_success39:                                 ; preds = %event_loss_counter34
  %25 = atomicrmw add ptr %lookup_elem38, i64 1 seq_cst, align 8
  br label %lookup_merge41

lookup_failure40:                                 ; preds = %event_loss_counter34
  br label %lookup_merge41

lookup_merge41:                                   ; preds = %lookup_failure40, %lookup_success39
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key37)
  br label %counter_merge35

lookup_success45:                                 ; preds = %helper_merge31
  %26 = load i64, ptr %lookup_elem44, align 8
  store i64 %26, ptr %lookup_elem_val48, align 8
  br label %lookup_merge47

lookup_failure46:                                 ; preds = %helper_merge31
  store i64 0, ptr %lookup_elem_val48, align 8
  br label %lookup_merge47

lookup_merge47:                                   ; preds = %lookup_failure46, %lookup_success45
  %27 = load i64, ptr %lookup_elem_val48, align 8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_elem_val48)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_newval50")
  %28 = sub i64 %27, 1
  store i64 %28, ptr %"@x_newval50", align 8
  %update_elem51 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %"@x_key43", ptr %"@x_newval50", i64 0)
  %29 = trunc i64 %update_elem51 to i32
  %30 = icmp sge i32 %29, 0
  br i1 %30, label %helper_merge53, label %helper_failure52

helper_failure52:                                 ; preds = %lookup_merge47
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t54)
  %31 = getelementptr %helper_error_t, ptr %helper_error_t54, i64 0, i32 0
  store i64 30006, ptr %31, align 8
  %32 = getelementptr %helper_error_t, ptr %helper_error_t54, i64 0, i32 1
  store i64 3, ptr %32, align 8
  %33 = getelementptr %helper_error_t, ptr %helper_error_t54, i64 0, i32 2
  store i32 %29, ptr %33, align 4
  %ringbuf_output55 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t54, i64 20, i64 0)
  %ringbuf_loss58 = icmp slt i64 %ringbuf_output55, 0
  br i1 %ringbuf_loss58, label %event_loss_counter56, label %counter_merge57

helper_merge53:                                   ; preds = %counter_merge57, %lookup_merge47
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_newval50")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key43")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_key65")
  store i64 0, ptr %"@x_key65", align 8
  %lookup_elem66 = call ptr inttoptr (i64 1 to ptr)(ptr @AT_x, ptr %"@x_key65")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_elem_val70)
  %map_lookup_cond71 = icmp ne ptr %lookup_elem66, null
  br i1 %map_lookup_cond71, label %lookup_success67, label %lookup_failure68

event_loss_counter56:                             ; preds = %helper_failure52
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key59)
  store i32 0, ptr %key59, align 4
  %lookup_elem60 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key59)
  %map_lookup_cond64 = icmp ne ptr %lookup_elem60, null
  br i1 %map_lookup_cond64, label %lookup_success61, label %lookup_failure62

counter_merge57:                                  ; preds = %lookup_merge63, %helper_failure52
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t54)
  br label %helper_merge53

lookup_success61:                                 ; preds = %event_loss_counter56
  %34 = atomicrmw add ptr %lookup_elem60, i64 1 seq_cst, align 8
  br label %lookup_merge63

lookup_failure62:                                 ; preds = %event_loss_counter56
  br label %lookup_merge63

lookup_merge63:                                   ; preds = %lookup_failure62, %lookup_success61
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key59)
  br label %counter_merge57

lookup_success67:                                 ; preds = %helper_merge53
  %35 = load i64, ptr %lookup_elem66, align 8
  store i64 %35, ptr %lookup_elem_val70, align 8
  br label %lookup_merge69

lookup_failure68:                                 ; preds = %helper_merge53
  store i64 0, ptr %lookup_elem_val70, align 8
  br label %lookup_merge69

lookup_merge69:                                   ; preds = %lookup_failure68, %lookup_success67
  %36 = load i64, ptr %lookup_elem_val70, align 8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_elem_val70)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@x_newval72")
  %37 = sub i64 %36, 1
  store i64 %37, ptr %"@x_newval72", align 8
  %update_elem73 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %"@x_key65", ptr %"@x_newval72", i64 0)
  %38 = trunc i64 %update_elem73 to i32
  %39 = icmp sge i32 %38, 0
  br i1 %39, label %helper_merge75, label %helper_failure74

helper_failure74:                                 ; preds = %lookup_merge69
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t76)
  %40 = getelementptr %helper_error_t, ptr %helper_error_t76, i64 0, i32 0
  store i64 30006, ptr %40, align 8
  %41 = getelementptr %helper_error_t, ptr %helper_error_t76, i64 0, i32 1
  store i64 4, ptr %41, align 8
  %42 = getelementptr %helper_error_t, ptr %helper_error_t76, i64 0, i32 2
  store i32 %38, ptr %42, align 4
  %ringbuf_output77 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t76, i64 20, i64 0)
  %ringbuf_loss80 = icmp slt i64 %ringbuf_output77, 0
  br i1 %ringbuf_loss80, label %event_loss_counter78, label %counter_merge79

helper_merge75:                                   ; preds = %counter_merge79, %lookup_merge69
  %43 = load i64, ptr %"@x_newval72", align 8
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_newval72")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@x_key65")
  ret i64 0

event_loss_counter78:                             ; preds = %helper_failure74
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key81)
  store i32 0, ptr %key81, align 4
  %lookup_elem82 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key81)
  %map_lookup_cond86 = icmp ne ptr %lookup_elem82, null
  br i1 %map_lookup_cond86, label %lookup_success83, label %lookup_failure84

counter_merge79:                                  ; preds = %lookup_merge85, %helper_failure74
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t76)
  br label %helper_merge75

lookup_success83:                                 ; preds = %event_loss_counter78
  %44 = atomicrmw add ptr %lookup_elem82, i64 1 seq_cst, align 8
  br label %lookup_merge85

lookup_failure84:                                 ; preds = %event_loss_counter78
  br label %lookup_merge85

lookup_merge85:                                   ; preds = %lookup_failure84, %lookup_success83
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key81)
  br label %counter_merge79
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
