; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr, ptr, ptr }
%"struct map_t.1" = type { ptr, ptr, ptr, ptr }
%"struct map_t.2" = type { ptr, ptr, ptr, ptr }
%"struct map_t.3" = type { ptr, ptr, ptr, ptr }
%"struct map_t.4" = type { ptr, ptr }
%"struct map_t.5" = type { ptr, ptr, ptr, ptr }
%helper_error_t = type <{ i64, i64, i32 }>

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_a = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@AT_b = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !16
@AT_c = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !18
@AT_d = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !20
@AT_e = dso_local global %"struct map_t.3" zeroinitializer, section ".maps", !dbg !22
@ringbuf = dso_local global %"struct map_t.4" zeroinitializer, section ".maps", !dbg !32
@event_loss_counter = dso_local global %"struct map_t.5" zeroinitializer, section ".maps", !dbg !46

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(ptr %0) section "s_kprobe_f_1" !dbg !61 {
entry:
  %key52 = alloca i32, align 4
  %helper_error_t47 = alloca %helper_error_t, align 8
  %"@e_key" = alloca i64, align 8
  %"struct x.e" = alloca [4 x i8], align 1
  %key37 = alloca i32, align 4
  %helper_error_t32 = alloca %helper_error_t, align 8
  %"@d_val" = alloca i64, align 8
  %"@d_key" = alloca i64, align 8
  %"struct c.c" = alloca i8, align 1
  %key23 = alloca i32, align 4
  %helper_error_t18 = alloca %helper_error_t, align 8
  %"@c_val" = alloca i64, align 8
  %"@c_key" = alloca i64, align 8
  %key9 = alloca i32, align 4
  %helper_error_t4 = alloca %helper_error_t, align 8
  %"@b_val" = alloca i64, align 8
  %"@b_key" = alloca i64, align 8
  %key = alloca i32, align 4
  %helper_error_t = alloca %helper_error_t, align 8
  %"@a_val" = alloca i64, align 8
  %"@a_key" = alloca i64, align 8
  %"$x" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$x")
  store i64 0, ptr %"$x", align 8
  store ptr %0, ptr %"$x", align 8
  %1 = load i64, ptr %"$x", align 8
  %2 = inttoptr i64 %1 to ptr
  %3 = call ptr @llvm.preserve.static.offset(ptr %2)
  %4 = getelementptr i8, ptr %3, i64 0
  %5 = load volatile i64, ptr %4, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@a_key")
  store i64 0, ptr %"@a_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@a_val")
  store i64 %5, ptr %"@a_val", align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_a, ptr %"@a_key", ptr %"@a_val", i64 0)
  %6 = trunc i64 %update_elem to i32
  %7 = icmp sge i32 %6, 0
  br i1 %7, label %helper_merge, label %helper_failure

helper_failure:                                   ; preds = %entry
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t)
  %8 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 0
  store i64 30006, ptr %8, align 8
  %9 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 1
  store i64 0, ptr %9, align 8
  %10 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 2
  store i32 %6, ptr %10, align 4
  %ringbuf_output = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t, i64 20, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

helper_merge:                                     ; preds = %counter_merge, %entry
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@a_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@a_key")
  %11 = load i64, ptr %"$x", align 8
  %12 = inttoptr i64 %11 to ptr
  %13 = call ptr @llvm.preserve.static.offset(ptr %12)
  %14 = getelementptr i8, ptr %13, i64 8
  %15 = ptrtoint ptr %14 to i64
  %16 = inttoptr i64 %15 to ptr
  %17 = call ptr @llvm.preserve.static.offset(ptr %16)
  %18 = getelementptr i8, ptr %17, i64 0
  %19 = load volatile i16, ptr %18, align 2
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@b_key")
  store i64 0, ptr %"@b_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@b_val")
  %20 = sext i16 %19 to i64
  store i64 %20, ptr %"@b_val", align 8
  %update_elem1 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_b, ptr %"@b_key", ptr %"@b_val", i64 0)
  %21 = trunc i64 %update_elem1 to i32
  %22 = icmp sge i32 %21, 0
  br i1 %22, label %helper_merge3, label %helper_failure2

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
  %23 = atomicrmw add ptr %lookup_elem, i64 1 seq_cst, align 8
  br label %lookup_merge

lookup_failure:                                   ; preds = %event_loss_counter
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key)
  br label %counter_merge

helper_failure2:                                  ; preds = %helper_merge
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t4)
  %24 = getelementptr %helper_error_t, ptr %helper_error_t4, i64 0, i32 0
  store i64 30006, ptr %24, align 8
  %25 = getelementptr %helper_error_t, ptr %helper_error_t4, i64 0, i32 1
  store i64 1, ptr %25, align 8
  %26 = getelementptr %helper_error_t, ptr %helper_error_t4, i64 0, i32 2
  store i32 %21, ptr %26, align 4
  %ringbuf_output5 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t4, i64 20, i64 0)
  %ringbuf_loss8 = icmp slt i64 %ringbuf_output5, 0
  br i1 %ringbuf_loss8, label %event_loss_counter6, label %counter_merge7

helper_merge3:                                    ; preds = %counter_merge7, %helper_merge
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@b_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@b_key")
  %27 = load i64, ptr %"$x", align 8
  %28 = inttoptr i64 %27 to ptr
  %29 = call ptr @llvm.preserve.static.offset(ptr %28)
  %30 = getelementptr i8, ptr %29, i64 16
  %31 = call ptr @llvm.preserve.static.offset(ptr %30)
  %32 = getelementptr i8, ptr %31, i64 0
  %33 = load volatile i8, ptr %32, align 1
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@c_key")
  store i64 0, ptr %"@c_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@c_val")
  %34 = sext i8 %33 to i64
  store i64 %34, ptr %"@c_val", align 8
  %update_elem15 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_c, ptr %"@c_key", ptr %"@c_val", i64 0)
  %35 = trunc i64 %update_elem15 to i32
  %36 = icmp sge i32 %35, 0
  br i1 %36, label %helper_merge17, label %helper_failure16

event_loss_counter6:                              ; preds = %helper_failure2
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key9)
  store i32 0, ptr %key9, align 4
  %lookup_elem10 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key9)
  %map_lookup_cond14 = icmp ne ptr %lookup_elem10, null
  br i1 %map_lookup_cond14, label %lookup_success11, label %lookup_failure12

counter_merge7:                                   ; preds = %lookup_merge13, %helper_failure2
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t4)
  br label %helper_merge3

lookup_success11:                                 ; preds = %event_loss_counter6
  %37 = atomicrmw add ptr %lookup_elem10, i64 1 seq_cst, align 8
  br label %lookup_merge13

lookup_failure12:                                 ; preds = %event_loss_counter6
  br label %lookup_merge13

lookup_merge13:                                   ; preds = %lookup_failure12, %lookup_success11
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key9)
  br label %counter_merge7

helper_failure16:                                 ; preds = %helper_merge3
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t18)
  %38 = getelementptr %helper_error_t, ptr %helper_error_t18, i64 0, i32 0
  store i64 30006, ptr %38, align 8
  %39 = getelementptr %helper_error_t, ptr %helper_error_t18, i64 0, i32 1
  store i64 2, ptr %39, align 8
  %40 = getelementptr %helper_error_t, ptr %helper_error_t18, i64 0, i32 2
  store i32 %35, ptr %40, align 4
  %ringbuf_output19 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t18, i64 20, i64 0)
  %ringbuf_loss22 = icmp slt i64 %ringbuf_output19, 0
  br i1 %ringbuf_loss22, label %event_loss_counter20, label %counter_merge21

helper_merge17:                                   ; preds = %counter_merge21, %helper_merge3
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@c_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@c_key")
  %41 = load i64, ptr %"$x", align 8
  %42 = inttoptr i64 %41 to ptr
  %43 = call ptr @llvm.preserve.static.offset(ptr %42)
  %44 = getelementptr i8, ptr %43, i64 24
  %45 = load volatile i64, ptr %44, align 8
  %46 = inttoptr i64 %45 to ptr
  %47 = call ptr @llvm.preserve.static.offset(ptr %46)
  %48 = getelementptr i8, ptr %47, i64 0
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"struct c.c")
  %probe_read_kernel = call i64 inttoptr (i64 113 to ptr)(ptr %"struct c.c", i32 1, ptr %48)
  %49 = load i8, ptr %"struct c.c", align 1
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"struct c.c")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@d_key")
  store i64 0, ptr %"@d_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@d_val")
  %50 = sext i8 %49 to i64
  store i64 %50, ptr %"@d_val", align 8
  %update_elem29 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_d, ptr %"@d_key", ptr %"@d_val", i64 0)
  %51 = trunc i64 %update_elem29 to i32
  %52 = icmp sge i32 %51, 0
  br i1 %52, label %helper_merge31, label %helper_failure30

event_loss_counter20:                             ; preds = %helper_failure16
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key23)
  store i32 0, ptr %key23, align 4
  %lookup_elem24 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key23)
  %map_lookup_cond28 = icmp ne ptr %lookup_elem24, null
  br i1 %map_lookup_cond28, label %lookup_success25, label %lookup_failure26

counter_merge21:                                  ; preds = %lookup_merge27, %helper_failure16
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t18)
  br label %helper_merge17

lookup_success25:                                 ; preds = %event_loss_counter20
  %53 = atomicrmw add ptr %lookup_elem24, i64 1 seq_cst, align 8
  br label %lookup_merge27

lookup_failure26:                                 ; preds = %event_loss_counter20
  br label %lookup_merge27

lookup_merge27:                                   ; preds = %lookup_failure26, %lookup_success25
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key23)
  br label %counter_merge21

helper_failure30:                                 ; preds = %helper_merge17
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t32)
  %54 = getelementptr %helper_error_t, ptr %helper_error_t32, i64 0, i32 0
  store i64 30006, ptr %54, align 8
  %55 = getelementptr %helper_error_t, ptr %helper_error_t32, i64 0, i32 1
  store i64 3, ptr %55, align 8
  %56 = getelementptr %helper_error_t, ptr %helper_error_t32, i64 0, i32 2
  store i32 %51, ptr %56, align 4
  %ringbuf_output33 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t32, i64 20, i64 0)
  %ringbuf_loss36 = icmp slt i64 %ringbuf_output33, 0
  br i1 %ringbuf_loss36, label %event_loss_counter34, label %counter_merge35

helper_merge31:                                   ; preds = %counter_merge35, %helper_merge17
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@d_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@d_key")
  %57 = load i64, ptr %"$x", align 8
  %58 = inttoptr i64 %57 to ptr
  %59 = call ptr @llvm.preserve.static.offset(ptr %58)
  %60 = getelementptr i8, ptr %59, i64 32
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"struct x.e")
  %probe_read_kernel43 = call i64 inttoptr (i64 113 to ptr)(ptr %"struct x.e", i32 4, ptr %60)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@e_key")
  store i64 0, ptr %"@e_key", align 8
  %update_elem44 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_e, ptr %"@e_key", ptr %"struct x.e", i64 0)
  %61 = trunc i64 %update_elem44 to i32
  %62 = icmp sge i32 %61, 0
  br i1 %62, label %helper_merge46, label %helper_failure45

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
  %63 = atomicrmw add ptr %lookup_elem38, i64 1 seq_cst, align 8
  br label %lookup_merge41

lookup_failure40:                                 ; preds = %event_loss_counter34
  br label %lookup_merge41

lookup_merge41:                                   ; preds = %lookup_failure40, %lookup_success39
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key37)
  br label %counter_merge35

helper_failure45:                                 ; preds = %helper_merge31
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t47)
  %64 = getelementptr %helper_error_t, ptr %helper_error_t47, i64 0, i32 0
  store i64 30006, ptr %64, align 8
  %65 = getelementptr %helper_error_t, ptr %helper_error_t47, i64 0, i32 1
  store i64 4, ptr %65, align 8
  %66 = getelementptr %helper_error_t, ptr %helper_error_t47, i64 0, i32 2
  store i32 %61, ptr %66, align 4
  %ringbuf_output48 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t47, i64 20, i64 0)
  %ringbuf_loss51 = icmp slt i64 %ringbuf_output48, 0
  br i1 %ringbuf_loss51, label %event_loss_counter49, label %counter_merge50

helper_merge46:                                   ; preds = %counter_merge50, %helper_merge31
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@e_key")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"struct x.e")
  ret i64 0

event_loss_counter49:                             ; preds = %helper_failure45
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key52)
  store i32 0, ptr %key52, align 4
  %lookup_elem53 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key52)
  %map_lookup_cond57 = icmp ne ptr %lookup_elem53, null
  br i1 %map_lookup_cond57, label %lookup_success54, label %lookup_failure55

counter_merge50:                                  ; preds = %lookup_merge56, %helper_failure45
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t47)
  br label %helper_merge46

lookup_success54:                                 ; preds = %event_loss_counter49
  %67 = atomicrmw add ptr %lookup_elem53, i64 1 seq_cst, align 8
  br label %lookup_merge56

lookup_failure55:                                 ; preds = %event_loss_counter49
  br label %lookup_merge56

lookup_merge56:                                   ; preds = %lookup_failure55, %lookup_success54
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key52)
  br label %counter_merge50
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare ptr @llvm.preserve.static.offset(ptr readnone %0) #2

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #2 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }

!llvm.dbg.cu = !{!58}
!llvm.module.flags = !{!60}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "AT_a", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
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
!17 = distinct !DIGlobalVariable(name: "AT_b", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!18 = !DIGlobalVariableExpression(var: !19, expr: !DIExpression())
!19 = distinct !DIGlobalVariable(name: "AT_c", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!20 = !DIGlobalVariableExpression(var: !21, expr: !DIExpression())
!21 = distinct !DIGlobalVariable(name: "AT_d", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!22 = !DIGlobalVariableExpression(var: !23, expr: !DIExpression())
!23 = distinct !DIGlobalVariable(name: "AT_e", linkageName: "global", scope: !2, file: !2, type: !24, isLocal: false, isDefinition: true)
!24 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !25)
!25 = !{!5, !11, !12, !26}
!26 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !27, size: 64, offset: 192)
!27 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !28, size: 64)
!28 = !DICompositeType(tag: DW_TAG_array_type, baseType: !29, size: 32, elements: !30)
!29 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!30 = !{!31}
!31 = !DISubrange(count: 4, lowerBound: 0)
!32 = !DIGlobalVariableExpression(var: !33, expr: !DIExpression())
!33 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !34, isLocal: false, isDefinition: true)
!34 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !35)
!35 = !{!36, !41}
!36 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !37, size: 64)
!37 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !38, size: 64)
!38 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !39)
!39 = !{!40}
!40 = !DISubrange(count: 27, lowerBound: 0)
!41 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !42, size: 64, offset: 64)
!42 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !43, size: 64)
!43 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !44)
!44 = !{!45}
!45 = !DISubrange(count: 262144, lowerBound: 0)
!46 = !DIGlobalVariableExpression(var: !47, expr: !DIExpression())
!47 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !48, isLocal: false, isDefinition: true)
!48 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !49)
!49 = !{!50, !11, !55, !15}
!50 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !51, size: 64)
!51 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !52, size: 64)
!52 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !53)
!53 = !{!54}
!54 = !DISubrange(count: 2, lowerBound: 0)
!55 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !56, size: 64, offset: 128)
!56 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !57, size: 64)
!57 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!58 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !59)
!59 = !{!0, !16, !18, !20, !22, !32, !46}
!60 = !{i32 2, !"Debug Info Version", i32 3}
!61 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !62, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !58, retainedNodes: !65)
!62 = !DISubroutineType(types: !63)
!63 = !{!14, !64}
!64 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !29, size: 64)
!65 = !{!66}
!66 = !DILocalVariable(name: "ctx", arg: 1, scope: !61, file: !2, type: !64)
