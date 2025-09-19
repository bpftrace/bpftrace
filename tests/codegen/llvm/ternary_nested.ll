; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%"struct map_internal_repr_t" = type { ptr, ptr }
%print_int_8_t = type <{ i64, i64, [8 x i8] }>

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@ringbuf = dso_local global %"struct map_internal_repr_t" zeroinitializer, section ".maps", !dbg !7
@__bt__event_loss_counter = dso_local externally_initialized global [1 x [1 x i64]] zeroinitializer, section ".data.event_loss_counter", !dbg !22
@__bt__max_cpu_id = dso_local externally_initialized constant i64 0, section ".rodata", !dbg !29

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

; Function Attrs: nounwind
define i64 @kprobe_f_1(ptr %0) #0 section "s_kprobe_f_1" !dbg !35 {
entry:
  %print_int_8_t = alloca %print_int_8_t, align 8
  %"$z" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$z")
  store i64 0, ptr %"$z", align 8
  %"$y" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$y")
  store i64 0, ptr %"$y", align 8
  %"$x" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$x")
  store i64 0, ptr %"$x", align 8
  store i64 1, ptr %"$x", align 8
  store i64 1, ptr %"$y", align 8
  store i64 1, ptr %"$z", align 8
  %1 = load i64, ptr %"$x", align 8
  %true_cond = icmp ne i64 %1, 0
  br i1 %true_cond, label %left, label %right

left:                                             ; preds = %entry
  %2 = load i64, ptr %"$y", align 8
  %true_cond3 = icmp ne i64 %2, 0
  br i1 %true_cond3, label %left1, label %right2

right:                                            ; preds = %entry
  %3 = load i64, ptr %"$y", align 8
  br label %done9

left1:                                            ; preds = %left
  %4 = load i64, ptr %"$z", align 8
  %true_cond6 = icmp ne i64 %4, 0
  br i1 %true_cond6, label %left4, label %right5

right2:                                           ; preds = %left
  %5 = load i64, ptr %"$z", align 8
  br label %done7

left4:                                            ; preds = %left1
  %6 = load i64, ptr %"$x", align 8
  br label %done

right5:                                           ; preds = %left1
  %7 = load i64, ptr %"$y", align 8
  br label %done

done:                                             ; preds = %right5, %left4
  %result = phi i64 [ %6, %left4 ], [ %7, %right5 ]
  br label %done7

done7:                                            ; preds = %right2, %done
  %result8 = phi i64 [ %result, %done ], [ %5, %right2 ]
  br label %done9

done9:                                            ; preds = %right, %done7
  %result10 = phi i64 [ %result8, %done7 ], [ %3, %right ]
  call void @llvm.lifetime.start.p0(i64 -1, ptr %print_int_8_t)
  %8 = getelementptr %print_int_8_t, ptr %print_int_8_t, i64 0, i32 0
  store i64 30007, ptr %8, align 8
  %9 = getelementptr %print_int_8_t, ptr %print_int_8_t, i64 0, i32 1
  store i64 0, ptr %9, align 8
  %10 = getelementptr %print_int_8_t, ptr %print_int_8_t, i32 0, i32 2
  call void @llvm.memset.p0.i64(ptr align 1 %10, i8 0, i64 8, i1 false)
  store i64 %result10, ptr %10, align 8
  %ringbuf_output = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %print_int_8_t, i64 24, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

event_loss_counter:                               ; preds = %done9
  %get_cpu_id = call i64 inttoptr (i64 8 to ptr)() #3
  %11 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded = and i64 %get_cpu_id, %11
  %12 = getelementptr [1 x [1 x i64]], ptr @__bt__event_loss_counter, i64 0, i64 %cpu.id.bounded, i64 0
  %13 = load i64, ptr %12, align 8
  %14 = add i64 %13, 1
  store i64 %14, ptr %12, align 8
  br label %counter_merge

counter_merge:                                    ; preds = %event_loss_counter, %done9
  call void @llvm.lifetime.end.p0(i64 -1, ptr %print_int_8_t)
  ret i64 0
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #2

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #2 = { nocallback nofree nounwind willreturn memory(argmem: write) }
attributes #3 = { memory(none) }

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
