; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%"struct map_internal_repr_t" = type { ptr, ptr }
%errorf_t.1 = type { i64, %errorf_args_t.0 }
%errorf_args_t.0 = type { i64 }
%errorf_t = type { i64, %errorf_args_t }
%errorf_args_t = type { i32 }

@LICENSE = global [4 x i8] c"GPL\00", section "license", !dbg !0
@ringbuf = dso_local global %"struct map_internal_repr_t" zeroinitializer, section ".maps", !dbg !7
@__bt__event_loss_counter = dso_local externally_initialized global [1 x [1 x i64]] zeroinitializer, section ".data.event_loss_counter", !dbg !22
@__bt__max_cpu_id = dso_local externally_initialized constant i64 0, section ".rodata", !dbg !29

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

; Function Attrs: nounwind
define i64 @kprobe_f_1(ptr %0) #0 section "s_kprobe_f_1" !dbg !35 {
entry:
  %errorf_args4 = alloca %errorf_t.1, align 8
  %"$$signal_internal_2_$ret" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$$signal_internal_2_$ret")
  store i64 0, ptr %"$$signal_internal_2_$ret", align 8
  %errorf_args = alloca %errorf_t, align 8
  %"$$signal_internal_2_$sig" = alloca i32, align 4
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"$$signal_internal_2_$sig")
  store i32 0, ptr %"$$signal_internal_2_$sig", align 4
  store i32 0, ptr %"$$signal_internal_2_$sig", align 4
  %1 = call ptr @llvm.preserve.static.offset(ptr %0)
  %2 = getelementptr i8, ptr %1, i64 112
  %arg0 = load volatile i64, ptr %2, align 8
  %cast = trunc i64 %arg0 to i32
  store i32 %cast, ptr %"$$signal_internal_2_$sig", align 4
  %3 = load i32, ptr %"$$signal_internal_2_$sig", align 4
  %4 = sext i32 %3 to i64
  %5 = icmp slt i64 %4, 1
  %true_cond = icmp ne i1 %5, false
  br i1 %true_cond, label %left, label %right

left:                                             ; preds = %entry
  call void @llvm.lifetime.start.p0(i64 -1, ptr %errorf_args)
  call void @llvm.memset.p0.i64(ptr align 1 %errorf_args, i8 0, i64 16, i1 false)
  %6 = getelementptr %errorf_t, ptr %errorf_args, i32 0, i32 0
  store i64 0, ptr %6, align 8
  %7 = getelementptr %errorf_t, ptr %errorf_args, i32 0, i32 1
  %8 = load i32, ptr %"$$signal_internal_2_$sig", align 4
  %9 = getelementptr %errorf_args_t, ptr %7, i32 0, i32 0
  store i32 %8, ptr %9, align 4
  %ringbuf_output = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %errorf_args, i64 16, i64 0)
  %ringbuf_loss = icmp slt i64 %ringbuf_output, 0
  br i1 %ringbuf_loss, label %event_loss_counter, label %counter_merge

right:                                            ; preds = %entry
  br label %done

event_loss_counter:                               ; preds = %left
  %get_cpu_id = call i64 inttoptr (i64 8 to ptr)() #5
  %10 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded = and i64 %get_cpu_id, %10
  %11 = getelementptr [1 x [1 x i64]], ptr @__bt__event_loss_counter, i64 0, i64 %cpu.id.bounded, i64 0
  %12 = load i64, ptr %11, align 8
  %13 = add i64 %12, 1
  store i64 %13, ptr %11, align 8
  br label %counter_merge

counter_merge:                                    ; preds = %event_loss_counter, %left
  call void @llvm.lifetime.end.p0(i64 -1, ptr %errorf_args)
  br label %done

done:                                             ; preds = %right, %counter_merge
  %14 = load i32, ptr %"$$signal_internal_2_$sig", align 4
  %__signal = call i64 @__signal(i32 %14), !dbg !41
  store i64 %__signal, ptr %"$$signal_internal_2_$ret", align 8
  %15 = load i64, ptr %"$$signal_internal_2_$ret", align 8
  %16 = icmp ne i64 %15, 0
  %true_cond3 = icmp ne i1 %16, false
  br i1 %true_cond3, label %left1, label %right2

left1:                                            ; preds = %done
  call void @llvm.lifetime.start.p0(i64 -1, ptr %errorf_args4)
  call void @llvm.memset.p0.i64(ptr align 1 %errorf_args4, i8 0, i64 16, i1 false)
  %17 = getelementptr %errorf_t.1, ptr %errorf_args4, i32 0, i32 0
  store i64 1, ptr %17, align 8
  %18 = getelementptr %errorf_t.1, ptr %errorf_args4, i32 0, i32 1
  %19 = load i64, ptr %"$$signal_internal_2_$ret", align 8
  %20 = getelementptr %errorf_args_t.0, ptr %18, i32 0, i32 0
  store i64 %19, ptr %20, align 8
  %ringbuf_output5 = call i64 inttoptr (i64 130 to ptr)(ptr @ringbuf, ptr %errorf_args4, i64 16, i64 0)
  %ringbuf_loss8 = icmp slt i64 %ringbuf_output5, 0
  br i1 %ringbuf_loss8, label %event_loss_counter6, label %counter_merge7

right2:                                           ; preds = %done
  br label %done11

event_loss_counter6:                              ; preds = %left1
  %get_cpu_id9 = call i64 inttoptr (i64 8 to ptr)() #5
  %21 = load i64, ptr @__bt__max_cpu_id, align 8
  %cpu.id.bounded10 = and i64 %get_cpu_id9, %21
  %22 = getelementptr [1 x [1 x i64]], ptr @__bt__event_loss_counter, i64 0, i64 %cpu.id.bounded10, i64 0
  %23 = load i64, ptr %22, align 8
  %24 = add i64 %23, 1
  store i64 %24, ptr %22, align 8
  br label %counter_merge7

counter_merge7:                                   ; preds = %event_loss_counter6, %left1
  call void @llvm.lifetime.end.p0(i64 -1, ptr %errorf_args4)
  br label %done11

done11:                                           ; preds = %right2, %counter_merge7
  ret i64 0
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare ptr @llvm.preserve.static.offset(ptr readnone %0) #2

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #3

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #1

; Function Attrs: alwaysinline nounwind
declare dso_local i64 @__signal(i32 noundef %0) #4

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #2 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }
attributes #3 = { nocallback nofree nounwind willreturn memory(argmem: write) }
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
!41 = !DILocation(line: 919, column: 10, scope: !35)
