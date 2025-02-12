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
@AT_y = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !16
@ringbuf = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !18
@event_loss_counter = dso_local global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !32
@map_key_buf = dso_local externally_initialized global [1 x [3 x [8 x i8]]] zeroinitializer, section ".data.map_key_buf", !dbg !44
@write_map_val_buf = dso_local externally_initialized global [1 x [1 x [8 x i8]]] zeroinitializer, section ".data.write_map_val_buf", !dbg !54
@max_cpu_id = dso_local externally_initialized constant i64 zeroinitializer, section ".rodata", !dbg !58
@read_map_val_buf = dso_local externally_initialized global [1 x [1 x [8 x i8]]] zeroinitializer, section ".data.read_map_val_buf", !dbg !60

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(ptr %0) section "s_kprobe_f_1" !dbg !65 {
entry:
  %key24 = alloca i32, align 4
  %helper_error_t19 = alloca %helper_error_t, align 8
  %key = alloca i32, align 4
  %helper_error_t = alloca %helper_error_t, align 8
  %get_cpu_id = call i64 inttoptr (i64 8 to ptr)()
  %1 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded = and i64 %get_cpu_id, %1
  %2 = getelementptr [1 x [3 x [8 x i8]]], ptr @map_key_buf, i64 0, i64 %cpu.id.bounded, i64 0, i64 0
  store i64 0, ptr %2, align 8
  %get_cpu_id1 = call i64 inttoptr (i64 8 to ptr)()
  %3 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded2 = and i64 %get_cpu_id1, %3
  %4 = getelementptr [1 x [1 x [8 x i8]]], ptr @write_map_val_buf, i64 0, i64 %cpu.id.bounded2, i64 0, i64 0
  store i64 1, ptr %4, align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_x, ptr %2, ptr %4, i64 0)
  %5 = trunc i64 %update_elem to i32
  %6 = icmp sge i32 %5, 0
  br i1 %6, label %helper_merge, label %helper_failure

helper_failure:                                   ; preds = %entry
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t)
  %7 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 0
  store i64 30006, ptr %7, align 8
  %8 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 1
  store i64 0, ptr %8, align 8
  %9 = getelementptr %helper_error_t, ptr %helper_error_t, i64 0, i32 2
  store i32 %5, ptr %9, align 4
  %ringbuf_output = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t, i64 20, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

helper_merge:                                     ; preds = %counter_merge, %entry
  %get_cpu_id3 = call i64 inttoptr (i64 8 to ptr)()
  %10 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded4 = and i64 %get_cpu_id3, %10
  %11 = getelementptr [1 x [3 x [8 x i8]]], ptr @map_key_buf, i64 0, i64 %cpu.id.bounded4, i64 1, i64 0
  store i64 0, ptr %11, align 8
  %lookup_elem5 = call ptr inttoptr (i64 1 to ptr)(ptr @AT_x, ptr %11)
  %get_cpu_id9 = call i64 inttoptr (i64 8 to ptr)()
  %12 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded10 = and i64 %get_cpu_id9, %12
  %13 = getelementptr [1 x [1 x [8 x i8]]], ptr @read_map_val_buf, i64 0, i64 %cpu.id.bounded10, i64 0, i64 0
  %map_lookup_cond11 = icmp ne ptr %lookup_elem5, null
  br i1 %map_lookup_cond11, label %lookup_success6, label %lookup_failure7

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
  %14 = atomicrmw add ptr %lookup_elem, i64 1 seq_cst, align 8
  br label %lookup_merge

lookup_failure:                                   ; preds = %event_loss_counter
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key)
  br label %counter_merge

lookup_success6:                                  ; preds = %helper_merge
  %15 = load i64, ptr %lookup_elem5, align 8
  store i64 %15, ptr %13, align 8
  br label %lookup_merge8

lookup_failure7:                                  ; preds = %helper_merge
  store i64 0, ptr %13, align 8
  br label %lookup_merge8

lookup_merge8:                                    ; preds = %lookup_failure7, %lookup_success6
  %16 = load i64, ptr %13, align 8
  %get_cpu_id12 = call i64 inttoptr (i64 8 to ptr)()
  %17 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded13 = and i64 %get_cpu_id12, %17
  %18 = getelementptr [1 x [3 x [8 x i8]]], ptr @map_key_buf, i64 0, i64 %cpu.id.bounded13, i64 2, i64 0
  store i64 0, ptr %18, align 8
  %get_cpu_id14 = call i64 inttoptr (i64 8 to ptr)()
  %19 = load i64, ptr @max_cpu_id, align 8
  %cpu.id.bounded15 = and i64 %get_cpu_id14, %19
  %20 = getelementptr [1 x [1 x [8 x i8]]], ptr @write_map_val_buf, i64 0, i64 %cpu.id.bounded15, i64 0, i64 0
  store i64 %16, ptr %20, align 8
  %update_elem16 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_y, ptr %18, ptr %20, i64 0)
  %21 = trunc i64 %update_elem16 to i32
  %22 = icmp sge i32 %21, 0
  br i1 %22, label %helper_merge18, label %helper_failure17

helper_failure17:                                 ; preds = %lookup_merge8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %helper_error_t19)
  %23 = getelementptr %helper_error_t, ptr %helper_error_t19, i64 0, i32 0
  store i64 30006, ptr %23, align 8
  %24 = getelementptr %helper_error_t, ptr %helper_error_t19, i64 0, i32 1
  store i64 1, ptr %24, align 8
  %25 = getelementptr %helper_error_t, ptr %helper_error_t19, i64 0, i32 2
  store i32 %21, ptr %25, align 4
  %ringbuf_output20 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %helper_error_t19, i64 20, i64 0)
  %ringbuf_loss23 = icmp slt i64 %ringbuf_output20, 0
  br i1 %ringbuf_loss23, label %event_loss_counter21, label %counter_merge22

helper_merge18:                                   ; preds = %counter_merge22, %lookup_merge8
  ret i64 0

event_loss_counter21:                             ; preds = %helper_failure17
  call void @llvm.lifetime.start.p0(i64 -1, ptr %key24)
  store i32 0, ptr %key24, align 4
  %lookup_elem25 = call ptr inttoptr (i64 1 to ptr)(ptr @event_loss_counter, ptr %key24)
  %map_lookup_cond29 = icmp ne ptr %lookup_elem25, null
  br i1 %map_lookup_cond29, label %lookup_success26, label %lookup_failure27

counter_merge22:                                  ; preds = %lookup_merge28, %helper_failure17
  call void @llvm.lifetime.end.p0(i64 -1, ptr %helper_error_t19)
  br label %helper_merge18

lookup_success26:                                 ; preds = %event_loss_counter21
  %26 = atomicrmw add ptr %lookup_elem25, i64 1 seq_cst, align 8
  br label %lookup_merge28

lookup_failure27:                                 ; preds = %event_loss_counter21
  br label %lookup_merge28

lookup_merge28:                                   ; preds = %lookup_failure27, %lookup_success26
  call void @llvm.lifetime.end.p0(i64 -1, ptr %key24)
  br label %counter_merge22
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }

!llvm.dbg.cu = !{!62}
!llvm.module.flags = !{!64}

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
!17 = distinct !DIGlobalVariable(name: "AT_y", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!18 = !DIGlobalVariableExpression(var: !19, expr: !DIExpression())
!19 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !20, isLocal: false, isDefinition: true)
!20 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !21)
!21 = !{!22, !27}
!22 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !23, size: 64)
!23 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !24, size: 64)
!24 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !25)
!25 = !{!26}
!26 = !DISubrange(count: 27, lowerBound: 0)
!27 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !28, size: 64, offset: 64)
!28 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !29, size: 64)
!29 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !30)
!30 = !{!31}
!31 = !DISubrange(count: 262144, lowerBound: 0)
!32 = !DIGlobalVariableExpression(var: !33, expr: !DIExpression())
!33 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !34, isLocal: false, isDefinition: true)
!34 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !35)
!35 = !{!36, !11, !41, !15}
!36 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !37, size: 64)
!37 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !38, size: 64)
!38 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !39)
!39 = !{!40}
!40 = !DISubrange(count: 2, lowerBound: 0)
!41 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !42, size: 64, offset: 128)
!42 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !43, size: 64)
!43 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!44 = !DIGlobalVariableExpression(var: !45, expr: !DIExpression())
!45 = distinct !DIGlobalVariable(name: "map_key_buf", linkageName: "global", scope: !2, file: !2, type: !46, isLocal: false, isDefinition: true)
!46 = !DICompositeType(tag: DW_TAG_array_type, baseType: !47, size: 192, elements: !9)
!47 = !DICompositeType(tag: DW_TAG_array_type, baseType: !48, size: 192, elements: !52)
!48 = !DICompositeType(tag: DW_TAG_array_type, baseType: !49, size: 64, elements: !50)
!49 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!50 = !{!51}
!51 = !DISubrange(count: 8, lowerBound: 0)
!52 = !{!53}
!53 = !DISubrange(count: 3, lowerBound: 0)
!54 = !DIGlobalVariableExpression(var: !55, expr: !DIExpression())
!55 = distinct !DIGlobalVariable(name: "write_map_val_buf", linkageName: "global", scope: !2, file: !2, type: !56, isLocal: false, isDefinition: true)
!56 = !DICompositeType(tag: DW_TAG_array_type, baseType: !57, size: 64, elements: !9)
!57 = !DICompositeType(tag: DW_TAG_array_type, baseType: !48, size: 64, elements: !9)
!58 = !DIGlobalVariableExpression(var: !59, expr: !DIExpression())
!59 = distinct !DIGlobalVariable(name: "max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !14, isLocal: false, isDefinition: true)
!60 = !DIGlobalVariableExpression(var: !61, expr: !DIExpression())
!61 = distinct !DIGlobalVariable(name: "read_map_val_buf", linkageName: "global", scope: !2, file: !2, type: !56, isLocal: false, isDefinition: true)
!62 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !63)
!63 = !{!0, !16, !18, !32, !44, !54, !58, !60}
!64 = !{i32 2, !"Debug Info Version", i32 3}
!65 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !66, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !62, retainedNodes: !69)
!66 = !DISubroutineType(types: !67)
!67 = !{!14, !68}
!68 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !49, size: 64)
!69 = !{!70}
!70 = !DILocalVariable(name: "ctx", arg: 1, scope: !65, file: !2, type: !68)
