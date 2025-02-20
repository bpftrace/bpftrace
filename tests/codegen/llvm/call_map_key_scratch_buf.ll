; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr, ptr, ptr }
%"struct map_t.1" = type { ptr, ptr }
%"struct map_t.2" = type { ptr, ptr, ptr, ptr }
%helper_error_t = type <{ i64, i64, i32 }>

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_x = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@AT_y = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !20
@ringbuf = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !22
@event_loss_counter = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !36
@map_key_buf = dso_local externally_initialized global [1 x [7 x [8 x i8]]] zeroinitializer, section ".data.map_key_buf", !dbg !53
@write_map_val_buf = dso_local externally_initialized global [1 x [1 x [8 x i8]]] zeroinitializer, section ".data.write_map_val_buf", !dbg !63
@max_cpu_id = dso_local externally_initialized constant i64 zeroinitializer, section ".rodata", !dbg !67
@read_map_val_buf = dso_local externally_initialized global [1 x [2 x [8 x i8]]] zeroinitializer, section ".data.read_map_val_buf", !dbg !69
@num_cpus = dso_local externally_initialized constant i64 zeroinitializer, section ".rodata", !dbg !73

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(ptr %0) section "s_kprobe_f_1" !dbg !78 {
entry:
  %key41 = alloca i32, align 4
  %helper_error_t36 = alloca %helper_error_t, align 8
  %key23 = alloca i32, align 4
  %helper_error_t18 = alloca %helper_error_t, align 8
  %initial_value14 = alloca i64, align 8
  %lookup_elem_val12 = alloca i64, align 8
  %key = alloca i32, align 4
  %helper_error_t = alloca %helper_error_t, align 8
  %initial_value = alloca i64, align 8
  %lookup_elem_val = alloca i64, align 8
  %get_cpu_id = call i64 inttoptr (i64 8 to ptr)()
  %1 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded = and i64 %get_cpu_id, %1
  %2 = getelementptr [1 x [7 x [8 x i8]]], ptr @map_key_buf, i64 0, i64 %cpu.id.bounded, i64 0, i64 0
  store i64 1, ptr %2, align 8
  %lookup_elem = call ptr inttoptr (i64 1 to ptr)(ptr @AT_x, ptr %2)
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
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %2, ptr %initial_value, i64 1)
  %5 = trunc i64 %update_elem to i32
  %6 = icmp sge i32 %5, 0
  br i1 %6, label %helper_merge, label %helper_failure

lookup_merge:                                     ; preds = %helper_merge, %lookup_success
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_elem_val)
  %log2 = call i64 @log2(i64 10, i64 0)
  %get_cpu_id6 = call i64 inttoptr (i64 8 to ptr)()
  %7 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded7 = and i64 %get_cpu_id6, %7
  %8 = getelementptr [1 x [7 x [8 x i8]]], ptr @map_key_buf, i64 0, i64 %cpu.id.bounded7, i64 1, i64 0
  store i64 %log2, ptr %8, align 8
  %lookup_elem8 = call ptr inttoptr (i64 1 to ptr)(ptr @AT_y, ptr %8)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_elem_val12)
  %map_lookup_cond13 = icmp ne ptr %lookup_elem8, null
  br i1 %map_lookup_cond13, label %lookup_success9, label %lookup_failure10

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

lookup_success9:                                  ; preds = %lookup_merge
  %13 = load i64, ptr %lookup_elem8, align 8
  %14 = add i64 %13, 1
  store i64 %14, ptr %lookup_elem8, align 8
  br label %lookup_merge11

lookup_failure10:                                 ; preds = %lookup_merge
  call void @llvm.lifetime.start.p0(i64 -1, ptr %initial_value14)
  store i64 1, ptr %initial_value14, align 8
  %update_elem15 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_y, ptr %8, ptr %initial_value14, i64 1)
  %15 = trunc i64 %update_elem15 to i32
  %16 = icmp sge i32 %15, 0
  br i1 %16, label %helper_merge17, label %helper_failure16

lookup_merge11:                                   ; preds = %helper_merge17, %lookup_success9
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_elem_val12)
  %get_cpu_id29 = call i64 inttoptr (i64 8 to ptr)()
  %17 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded30 = and i64 %get_cpu_id29, %17
  %18 = getelementptr [1 x [7 x [8 x i8]]], ptr @map_key_buf, i64 0, i64 %cpu.id.bounded30, i64 2, i64 0
  store i64 1, ptr %18, align 8
  %lookup_elem31 = call ptr inttoptr (i64 1 to ptr)(ptr @AT_x, ptr %18)
  %has_key = icmp ne ptr %lookup_elem31, null
  %get_cpu_id32 = call i64 inttoptr (i64 8 to ptr)()
  %19 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded33 = and i64 %get_cpu_id32, %19
  %20 = getelementptr [1 x [7 x [8 x i8]]], ptr @map_key_buf, i64 0, i64 %cpu.id.bounded33, i64 3, i64 0
  store i64 1, ptr %20, align 8
  %delete_elem = call i64 inttoptr (i64 3 to ptr)(ptr @AT_x, ptr %20)
  %21 = trunc i64 %delete_elem to i32
  %22 = icmp sge i32 %21, 0
  br i1 %22, label %helper_merge35, label %helper_failure34

helper_failure16:                                 ; preds = %lookup_failure10
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t18)
  %23 = getelementptr %helper_error_t, ptr %helper_error_t18, i64 0, i32 0
  store i64 30006, ptr %23, align 8
  %24 = getelementptr %helper_error_t, ptr %helper_error_t18, i64 0, i32 1
  store i64 1, ptr %24, align 8
  %25 = getelementptr %helper_error_t, ptr %helper_error_t18, i64 0, i32 2
  store i32 %15, ptr %25, align 4
  %ringbuf_output19 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t18, i64 20, i64 0)
  %ringbuf_loss22 = icmp slt i64 %ringbuf_output19, 0
  br i1 %ringbuf_loss22, label %event_loss_counter20, label %counter_merge21

helper_merge17:                                   ; preds = %counter_merge21, %lookup_failure10
  call void @llvm.lifetime.end.p0(i64 -1, ptr %initial_value14)
  br label %lookup_merge11

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
  %26 = atomicrmw add ptr %lookup_elem24, i64 1 seq_cst, align 8
  br label %lookup_merge27

lookup_failure26:                                 ; preds = %event_loss_counter20
  br label %lookup_merge27

lookup_merge27:                                   ; preds = %lookup_failure26, %lookup_success25
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key23)
  br label %counter_merge21

helper_failure34:                                 ; preds = %lookup_merge11
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t36)
  %27 = getelementptr %helper_error_t, ptr %helper_error_t36, i64 0, i32 0
  store i64 30006, ptr %27, align 8
  %28 = getelementptr %helper_error_t, ptr %helper_error_t36, i64 0, i32 1
  store i64 2, ptr %28, align 8
  %29 = getelementptr %helper_error_t, ptr %helper_error_t36, i64 0, i32 2
  store i32 %21, ptr %29, align 4
  %ringbuf_output37 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t36, i64 20, i64 0)
  %ringbuf_loss40 = icmp slt i64 %ringbuf_output37, 0
  br i1 %ringbuf_loss40, label %event_loss_counter38, label %counter_merge39

helper_merge35:                                   ; preds = %counter_merge39, %lookup_merge11
  ret i64 0

event_loss_counter38:                             ; preds = %helper_failure34
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key41)
  store i32 0, ptr %key41, align 4
  %lookup_elem42 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key41)
  %map_lookup_cond46 = icmp ne ptr %lookup_elem42, null
  br i1 %map_lookup_cond46, label %lookup_success43, label %lookup_failure44

counter_merge39:                                  ; preds = %lookup_merge45, %helper_failure34
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t36)
  br label %helper_merge35

lookup_success43:                                 ; preds = %event_loss_counter38
  %30 = atomicrmw add ptr %lookup_elem42, i64 1 seq_cst, align 8
  br label %lookup_merge45

lookup_failure44:                                 ; preds = %event_loss_counter38
  br label %lookup_merge45

lookup_merge45:                                   ; preds = %lookup_failure44, %lookup_success43
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key41)
  br label %counter_merge39
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: alwaysinline
define internal i64 @log2(i64 %0, i64 %1) #2 section "helpers" {
entry:
  %2 = alloca i64, align 8
  %3 = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %3)
  store i64 %0, ptr %3, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %2)
  store i64 %1, ptr %2, align 8
  %4 = load i64, ptr %3, align 8
  %5 = icmp slt i64 %4, 0
  br i1 %5, label %hist.is_less_than_zero, label %hist.is_not_less_than_zero

hist.is_less_than_zero:                           ; preds = %entry
  ret i64 0

hist.is_not_less_than_zero:                       ; preds = %entry
  %6 = load i64, ptr %2, align 8
  %7 = shl i64 1, %6
  %8 = sub i64 %7, 1
  %9 = icmp ule i64 %4, %8
  br i1 %9, label %hist.is_zero, label %hist.is_not_zero

hist.is_zero:                                     ; preds = %hist.is_not_less_than_zero
  %10 = add i64 %4, 1
  ret i64 %10

hist.is_not_zero:                                 ; preds = %hist.is_not_less_than_zero
  %11 = icmp sge i64 %4, 4294967296
  %12 = zext i1 %11 to i64
  %13 = shl i64 %12, 5
  %14 = lshr i64 %4, %13
  %15 = add i64 0, %13
  %16 = icmp sge i64 %14, 65536
  %17 = zext i1 %16 to i64
  %18 = shl i64 %17, 4
  %19 = lshr i64 %14, %18
  %20 = add i64 %15, %18
  %21 = icmp sge i64 %19, 256
  %22 = zext i1 %21 to i64
  %23 = shl i64 %22, 3
  %24 = lshr i64 %19, %23
  %25 = add i64 %20, %23
  %26 = icmp sge i64 %24, 16
  %27 = zext i1 %26 to i64
  %28 = shl i64 %27, 2
  %29 = lshr i64 %24, %28
  %30 = add i64 %25, %28
  %31 = icmp sge i64 %29, 4
  %32 = zext i1 %31 to i64
  %33 = shl i64 %32, 1
  %34 = lshr i64 %29, %33
  %35 = add i64 %30, %33
  %36 = icmp sge i64 %34, 2
  %37 = zext i1 %36 to i64
  %38 = shl i64 %37, 0
  %39 = lshr i64 %34, %38
  %40 = add i64 %35, %38
  %41 = sub i64 %40, %6
  %42 = load i64, ptr %3, align 8
  %43 = lshr i64 %42, %41
  %44 = and i64 %43, %8
  %45 = add i64 %41, 1
  %46 = shl i64 %45, %6
  %47 = add i64 %46, %44
  %48 = add i64 %47, 1
  ret i64 %48
}

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #2 = { alwaysinline }

!llvm.dbg.cu = !{!75}
!llvm.module.flags = !{!77}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "AT_x", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !4)
!4 = !{!5, !11, !16, !19}
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
!18 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!19 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !17, size: 64, offset: 192)
!20 = !DIGlobalVariableExpression(var: !21, expr: !DIExpression())
!21 = distinct !DIGlobalVariable(name: "AT_y", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!22 = !DIGlobalVariableExpression(var: !23, expr: !DIExpression())
!23 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !24, isLocal: false, isDefinition: true)
!24 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !25)
!25 = !{!26, !31}
!26 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !27, size: 64)
!27 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !28, size: 64)
!28 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !29)
!29 = !{!30}
!30 = !DISubrange(count: 27, lowerBound: 0)
!31 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !32, size: 64, offset: 64)
!32 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !33, size: 64)
!33 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !34)
!34 = !{!35}
!35 = !DISubrange(count: 262144, lowerBound: 0)
!36 = !DIGlobalVariableExpression(var: !37, expr: !DIExpression())
!37 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !38, isLocal: false, isDefinition: true)
!38 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !39)
!39 = !{!40, !45, !50, !19}
!40 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !41, size: 64)
!41 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !42, size: 64)
!42 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !43)
!43 = !{!44}
!44 = !DISubrange(count: 2, lowerBound: 0)
!45 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !46, size: 64, offset: 64)
!46 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !47, size: 64)
!47 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 32, elements: !48)
!48 = !{!49}
!49 = !DISubrange(count: 1, lowerBound: 0)
!50 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !51, size: 64, offset: 128)
!51 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !52, size: 64)
!52 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!53 = !DIGlobalVariableExpression(var: !54, expr: !DIExpression())
!54 = distinct !DIGlobalVariable(name: "map_key_buf", linkageName: "global", scope: !2, file: !2, type: !55, isLocal: false, isDefinition: true)
!55 = !DICompositeType(tag: DW_TAG_array_type, baseType: !56, size: 448, elements: !48)
!56 = !DICompositeType(tag: DW_TAG_array_type, baseType: !57, size: 448, elements: !61)
!57 = !DICompositeType(tag: DW_TAG_array_type, baseType: !58, size: 64, elements: !59)
!58 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!59 = !{!60}
!60 = !DISubrange(count: 8, lowerBound: 0)
!61 = !{!62}
!62 = !DISubrange(count: 7, lowerBound: 0)
!63 = !DIGlobalVariableExpression(var: !64, expr: !DIExpression())
!64 = distinct !DIGlobalVariable(name: "write_map_val_buf", linkageName: "global", scope: !2, file: !2, type: !65, isLocal: false, isDefinition: true)
!65 = !DICompositeType(tag: DW_TAG_array_type, baseType: !66, size: 64, elements: !48)
!66 = !DICompositeType(tag: DW_TAG_array_type, baseType: !57, size: 64, elements: !48)
!67 = !DIGlobalVariableExpression(var: !68, expr: !DIExpression())
!68 = distinct !DIGlobalVariable(name: "max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !18, isLocal: false, isDefinition: true)
!69 = !DIGlobalVariableExpression(var: !70, expr: !DIExpression())
!70 = distinct !DIGlobalVariable(name: "read_map_val_buf", linkageName: "global", scope: !2, file: !2, type: !71, isLocal: false, isDefinition: true)
!71 = !DICompositeType(tag: DW_TAG_array_type, baseType: !72, size: 128, elements: !48)
!72 = !DICompositeType(tag: DW_TAG_array_type, baseType: !57, size: 128, elements: !43)
!73 = !DIGlobalVariableExpression(var: !74, expr: !DIExpression())
!74 = distinct !DIGlobalVariable(name: "num_cpus", linkageName: "global", scope: !2, file: !2, type: !18, isLocal: false, isDefinition: true)
!75 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !76)
!76 = !{!0, !20, !22, !36, !53, !63, !67, !69, !73}
!77 = !{i32 2, !"Debug Info Version", i32 3}
!78 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !79, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !75, retainedNodes: !82)
!79 = !DISubroutineType(types: !80)
!80 = !{!18, !81}
!81 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !58, size: 64)
!82 = !{!83}
!83 = !DILocalVariable(name: "ctx", arg: 1, scope: !78, file: !2, type: !81)
