; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%"struct map_internal_repr_t" = type { ptr, ptr }
%warnf_t = type { i64, %warnf_args_t }
%warnf_args_t = type { i64 }
%errorf_t = type { i64, %errorf_args_t }
%errorf_args_t = type { [16 x i8], i32 }

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@ringbuf = dso_local global %"struct map_internal_repr_t" zeroinitializer, section ".maps", !dbg !7
@__bt__event_loss_counter = dso_local externally_initialized global [1 x [1 x i64]] zeroinitializer, section ".data.event_loss_counter", !dbg !22
@__bt__max_cpu_id = dso_local externally_initialized constant i64 0, section ".rodata", !dbg !29
@"signal_thread()" = global [16 x i8] c"signal_thread()\00"

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

; Function Attrs: nounwind
define i64 @kprobe_f_1(ptr %0) #0 section "s_kprobe_f_1" !dbg !35 {
entry:
  %warnf_args = alloca %warnf_t, align 8
  %"_1___signal_2_$ret" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"_1___signal_2_$ret")
  store i64 0, ptr %"_1___signal_2_$ret", align 8
  %errorf_args = alloca %errorf_t, align 8
  %"_1___signal_2_$sig" = alloca i32, align 4
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"_1___signal_2_$sig")
  store i32 0, ptr %"_1___signal_2_$sig", align 4
  store i32 0, ptr %"_1___signal_2_$sig", align 4
  store i32 8, ptr %"_1___signal_2_$sig", align 4
  %1 = load i32, ptr %"_1___signal_2_$sig", align 4
  %2 = sext i32 %1 to i64
  %3 = icmp slt i64 %2, 1
  %true_cond = icmp ne i1 %3, false
  br i1 %true_cond, label %left, label %right

left:                                             ; preds = %entry
  call void @llvm.lifetime.start.p0(i64 -1, ptr %errorf_args)
  call void @llvm.memset.p0.i64(ptr align 1 %errorf_args, i8 0, i64 32, i1 false)
  %4 = getelementptr %errorf_t, ptr %errorf_args, i32 0, i32 0
  store i64 0, ptr %4, align 8
  %5 = getelementptr %errorf_t, ptr %errorf_args, i32 0, i32 1
  %6 = getelementptr %errorf_args_t, ptr %5, i32 0, i32 0
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %6, ptr align 1 @"signal_thread()", i64 16, i1 false)
  %7 = load i32, ptr %"_1___signal_2_$sig", align 4
  %8 = getelementptr %errorf_args_t, ptr %5, i32 0, i32 1
  store i32 %7, ptr %8, align 4
  %ringbuf_output = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %errorf_args, i64 32, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

right:                                            ; preds = %entry
  %9 = load i32, ptr %"_1___signal_2_$sig", align 4
  %__signal_thread = call i64 @__signal_thread(i32 %9), !dbg !41
  store i64 %__signal_thread, ptr %"_1___signal_2_$ret", align 8
  %10 = load i64, ptr %"_1___signal_2_$ret", align 8
  %11 = icmp ne i64 %10, 0
  %true_cond3 = icmp ne i1 %11, false
  br i1 %true_cond3, label %left1, label %right2

event_loss_counter:                               ; preds = %left
  %get_cpu_id = call i64 inttoptr (i64 8 to ptr)() #5
  %12 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded = and i64 %get_cpu_id, %12
  %13 = getelementptr [1 x [1 x i64]], ptr @__bt__event_loss_counter, i64 0, i64 %cpu.id.bounded, i64 0
  %14 = load i64, ptr %13, align 8
  %15 = add i64 %14, 1
  store i64 %15, ptr %13, align 8
  br label %counter_merge

counter_merge:                                    ; preds = %event_loss_counter, %left
  call void @llvm.lifetime.end.p0(i64 -1, ptr %errorf_args)
  br label %done

done:                                             ; preds = %done10, %counter_merge
  ret i64 0

left1:                                            ; preds = %right
  call void @llvm.lifetime.start.p0(i64 -1, ptr %warnf_args)
  call void @llvm.memset.p0.i64(ptr align 1 %warnf_args, i8 0, i64 16, i1 false)
  %16 = getelementptr %warnf_t, ptr %warnf_args, i32 0, i32 0
  store i64 1, ptr %16, align 8
  %17 = getelementptr %warnf_t, ptr %warnf_args, i32 0, i32 1
  %18 = load i64, ptr %"_1___signal_2_$ret", align 8
  %19 = getelementptr %warnf_args_t, ptr %17, i32 0, i32 0
  store i64 %18, ptr %19, align 8
  %ringbuf_output4 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %warnf_args, i64 16, i64 0)
  %ringbuf_loss7 = icmp slt i64 %ringbuf_output4, 0
  br i1 %ringbuf_loss7, label %event_loss_counter5, label %counter_merge6

right2:                                           ; preds = %right
  br label %done10

event_loss_counter5:                              ; preds = %left1
  %get_cpu_id8 = call i64 inttoptr (i64 8 to ptr)() #5
  %20 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded9 = and i64 %get_cpu_id8, %20
  %21 = getelementptr [1 x [1 x i64]], ptr @__bt__event_loss_counter, i64 0, i64 %cpu.id.bounded9, i64 0
  %22 = load i64, ptr %21, align 8
  %23 = add i64 %22, 1
  store i64 %23, ptr %21, align 8
  br label %counter_merge6

counter_merge6:                                   ; preds = %event_loss_counter5, %left1
  call void @llvm.lifetime.end.p0(i64 -1, ptr %warnf_args)
  br label %done10

done10:                                           ; preds = %right2, %counter_merge6
  br label %done
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: readwrite)
declare void @llvm.memcpy.p0.p0.i64(ptr noalias nocapture writeonly %0, ptr noalias nocapture readonly %1, i64 %2, i1 immarg %3) #3

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: alwaysinline nounwind
declare dso_local i64 @__signal_thread(i32 noundef %0) #4

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #2 = { nocallback nofree nounwind willreturn memory(argmem: write) }
attributes #3 = { nocallback nofree nounwind willreturn memory(argmem: readwrite) }
attributes #4 = { alwaysinline nounwind }
attributes #5 = { memory(none) }

!llvm.dbg.cu = !{!31}
!llvm.module.flags = !{!33, !34}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "LICENSE", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 32, elements: !5)
!4 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!5 = !{!6}
!6 = !DISubrange(count: 4, lowerBound: 0)
!7 = !DIGlobalVariableExpression(var: !8, expr: !DIExpression())
!8 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !9, isLocal: false, isDefinition: true)
!9 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !10)
!10 = !{!11, !17}
!11 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !12, size: 64)
!12 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !13, size: 64)
!13 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 864, elements: !15)
!14 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!15 = !{!16}
!16 = !DISubrange(count: 27, lowerBound: 0)
!17 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !18, size: 64, offset: 64)
!18 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !19, size: 64)
!19 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 8388608, elements: !20)
!20 = !{!21}
!21 = !DISubrange(count: 262144, lowerBound: 0)
!22 = !DIGlobalVariableExpression(var: !23, expr: !DIExpression())
!23 = distinct !DIGlobalVariable(name: "__bt__event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !24, isLocal: false, isDefinition: true)
!24 = !DICompositeType(tag: DW_TAG_array_type, baseType: !25, size: 64, elements: !27)
!25 = !DICompositeType(tag: DW_TAG_array_type, baseType: !26, size: 64, elements: !27)
!26 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!27 = !{!28}
!28 = !DISubrange(count: 1, lowerBound: 0)
!29 = !DIGlobalVariableExpression(var: !30, expr: !DIExpression())
!30 = distinct !DIGlobalVariable(name: "__bt__max_cpu_id", linkageName: "global", scope: !2, file: !2, type: !26, isLocal: false, isDefinition: true)
!31 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !32)
!32 = !{!0, !7, !22, !29}
!33 = !{i32 2, !"Debug Info Version", i32 3}
!34 = !{i32 7, !"uwtable", i32 0}
!35 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !36, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !31, retainedNodes: !39)
!36 = !DISubroutineType(types: !37)
!37 = !{!26, !38}
!38 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!39 = !{!40}
!40 = !DILocalVariable(name: "ctx", arg: 1, scope: !35, file: !2, type: !38)
!41 = !DILocation(line: 38, column: 30, scope: !35)
